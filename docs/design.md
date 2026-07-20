# BPF DNS Gateway — Design Document

## 1. Problem Statement

On EKS, pods resolve all DNS queries through CoreDNS (the cluster DNS service). For AWS service endpoints — S3, ECR, STS, etc. — this adds an unnecessary hop. CoreDNS ultimately forwards these queries to the VPC DNS resolver anyway, but the extra hop through CoreDNS adds latency, increases CoreDNS load, and can become a bottleneck at scale.

More critically, some AWS service DNS responses are topology-aware (e.g., S3 gateway endpoint resolution). When CoreDNS forwards these queries, the response may be optimized for CoreDNS's location rather than the pod's actual node, which can result in suboptimal routing.

**Goal**: Transparently intercept DNS queries from pods and route specific queries (matching configurable suffix patterns) directly to the host's VPC DNS resolver, bypassing CoreDNS. All other queries proceed to CoreDNS normally. The interception must be invisible to pods — responses appear to originate from CoreDNS.

## 2. Design Priorities

1. **Correctness** — Never misroute or drop DNS queries. Every failure mode falls back to CoreDNS.
2. **Simplicity** — Minimal moving parts. No userspace proxy. No Kubernetes API dependency at runtime.
3. **Availability** — If the component fails, DNS must continue working through CoreDNS.
4. **Observability** — Prometheus metrics for every routing decision, error, and edge case.
5. **Resiliency** — Graceful handling of host resolver failures, process crashes, and node lifecycle events.

## 3. Architecture Overview

```
                          Pod Network Namespace
                         ┌─────────────────────┐
                         │  Pod sends DNS query │
                         │  dst = CoreDNS:53    │
                         │  (10.100.0.10:53)    │
                         └─────────┬───────────┘
                                   │ veth pair
                    ───────────────┼───────────────
                          Host Network Namespace
                                   │
                    ┌──────────────▼──────────────┐
                    │  TC eBPF INGRESS             │
                    │  (host-side veth)            │
                    │                              │
                    │  1. Parse ETH → IP → UDP     │
                    │  2. Match dst=CoreDNS:53?    │
                    │  3. Parse DNS wire format    │
                    │  4. Extract QNAME            │
                    │  5. Suffix match (hash map)  │
                    │                              │
                    │  Match → DNAT dst to VPC DNS │
                    │  No match → passthrough      │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │  Kernel routing              │
                    │                              │
                    │  Matched: → VPC DNS resolver │
                    │  Unmatched: → CoreDNS pod    │
                    └──────────────┬──────────────┘
                                   │
                              (DNS response)
                                   │
                    ┌──────────────▼──────────────┐
                    │  TC eBPF EGRESS              │
                    │  (host-side veth)            │
                    │                              │
                    │  If src = VPC DNS:53         │
                    │  and conntrack entry exists: │
                    │  SNAT src → CoreDNS:53       │
                    │                              │
                    │  Pod sees response from      │
                    │  CoreDNS (transparent)       │
                    └─────────────────────────────┘
```

### Components

| Component | Description |
|-----------|-------------|
| **eBPF TC programs** (C) | Ingress: DNS parse + suffix match + DNAT. Egress: conntrack lookup + SNAT. Attached to host-side of every pod veth. |
| **Controller** (Go) | Systemd service. Subscribes to netlink veth events. Loads eBPF programs, attaches to veths, populates BPF maps from config file. Health-checks VPC DNS resolver. Exports Prometheus metrics. |

### What this is NOT

- **Primarily not a Kubernetes component** — the recommended path is a systemd service baked into the node AMI: no K8s API dependency at runtime, no RBAC, and it starts before kubelet. An **optional** DaemonSet path is also provided (`deploy/daemonset.yaml`) for clusters that prefer a K8s-native rollout; it trades away start-before-kubelet and adds a K8s-API dependency at rollout time but requires no code changes (the running pod still only uses a config file + netlink + bpffs). See `docs/audit/001-daemonset-deployment.md`.
- **Not a DNS proxy** — no userspace packet handling. All DNS parsing and routing decisions happen in eBPF in the kernel.
- **Not a DNS cache** — queries are forwarded as-is. CoreDNS and VPC DNS have their own caches.

## 4. Deployment Model

The binary runs as a **systemd service** installed in the node AMI, starting before kubelet.

```ini
[Unit]
Description=BPF DNS Gateway
After=network.target
Before=kubelet.service

[Service]
Type=notify
ExecStart=/usr/local/bin/bpf-dns-gateway --config /etc/bpf-dns-gateway/config.yaml
Restart=always
RestartSec=5
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

**Why systemd over DaemonSet:**
- Starts before kubelet — eBPF is ready before any pod sends DNS
- No Kubernetes API dependency — works even if the API server is unreachable
- Survives kubelet restarts
- Simpler: no client-go, no RBAC, no pod informer
- Config is a static file on disk (baked into AMI or dropped by userdata)

## 5. Veth Lifecycle Management

Instead of watching the Kubernetes API for pod events, the controller subscribes to **netlink RTM_NEWLINK / RTM_DELLINK** events to discover veth interfaces as they are created and destroyed.

```
netlink socket (RTNLGRP_LINK)
         │
    RTM_NEWLINK ──→ Is it a veth? ──→ Attach TC eBPF ingress + egress
         │
    RTM_DELLINK ──→ Cleanup tracking state (eBPF auto-detaches)
```

**Filtering**: The controller attaches to **all** new veth interfaces. This is safe because the eBPF programs only act on UDP packets destined to the configured CoreDNS IP on port 53. All other traffic passes through untouched via `TC_ACT_OK`.

**Startup reconciliation**: On startup, enumerate all existing veth interfaces via `netlink.LinkList()` and attach eBPF to any that don't already have our programs.

### 5.1 VPC CNI Network Policy Coexistence

**Out of scope for MVP.** The MVP assumes our programs are the sole TC filter on host-side veths. Coexistence with VPC CNI network policy (priority ordering, `BPF_F_AFTER`/`BPF_F_BEFORE` positioning) is captured separately — see [`vpc-cni-coexistence.md`](./vpc-cni-coexistence.md).

## 6. eBPF Program Design

### 6.1 BPF Maps

```
┌─────────────────────────────────────────────────────────────┐
│ suffix_rules   HASH          1024 entries                    │
│ Key:   [256]byte  (wire-format DNS suffix, lowercase, 0-pad)│
│ Value: {action u32}                                          │
│                                                              │
│ config_map     ARRAY(1)      1 entry                         │
│ Key:   u32 (always 0)                                        │
│ Value: {coredns_ip, host_resolver_ip, dns_port, bypass}      │
│        (all IPs/ports in network byte order)                 │
│                                                              │
│ conntrack_map  LRU_HASH      65536 entries                   │
│ Key:   {pod_ip u32, pod_port u16, txid u16}                  │
│ Value: {coredns_ip u32, timestamp_ns u64}                    │
│                                                              │
│ metrics_map    PERCPU_ARRAY  9 entries                        │
│ Key:   u32 (metric ID)                                       │
│ Value: u64 (counter)                                         │
│                                                              │
│ scratch_map    PERCPU_ARRAY(1)  1 entry                      │
│ Key:   u32 (always 0)                                        │
│ Value: {qname [256]byte, lookup [256]byte}                   │
│        (off-stack scratch for DNS parsing)                   │
└─────────────────────────────────────────────────────────────┘
```

**Why per-CPU scratch map**: The BPF stack limit is 512 bytes. We need 256 bytes for the extracted QNAME and 256 bytes for the suffix lookup buffer. Placing these in a per-CPU array map keeps the stack at ~112 bytes (headers + locals). Per-CPU means no locking.

**Why LRU_HASH for conntrack**: Automatic eviction on overflow — no userspace garbage collection needed for correctness. DNS transactions are short-lived (~1–50ms), so 65K entries provides massive headroom.

**Why include `txid` in the key**: Real resolvers fire concurrent A and AAAA queries from the same source port with different DNS transaction IDs. Without `txid`, the two queries collide on a single conntrack entry, and one of the responses leaks `src=host_resolver_ip` to the pod. Adding `txid` makes each in-flight query distinct.

**Why egress checks TTL on `timestamp_ns`**: Even with `txid`, an LRU entry could persist long enough for an unrelated direct VPC-DNS response (pod talking to VPC DNS via another path) to coincidentally match `{pod_ip, pod_port, txid}` and be wrongly SNAT'd. Egress checks `now - timestamp_ns < CONNTRACK_TTL_NS` (default 5s); expired entries are deleted and the packet passes through unmodified.

### 6.2 Ingress Program (TC ingress on host-side veth)

Intercepts DNS queries from pods to CoreDNS. On suffix match, DNATs destination to VPC DNS resolver.

```
dns_gateway_ingress(skb):
    cfg = config_map[0]
    if !cfg or cfg.bypass → TC_ACT_OK

    load ETH header via bpf_skb_load_bytes
    if not IPv4 → TC_ACT_OK

    load IP header
    if protocol != UDP → TC_ACT_OK
    if daddr != cfg.coredns_ip → TC_ACT_OK
    if ihl < 5 or ihl > 15 → TC_ACT_OK

    load UDP header
    if dport != 53 → TC_ACT_OK

    load DNS header (12 bytes)
    if QR bit set (response) → TC_ACT_OK
    if QDCOUNT != 1 → TC_ACT_OK (passthrough; multi-question packets ambiguous)
    extract txid (DNS hdr bytes 0..1) for conntrack key

    // --- DNS QNAME extraction ---
    scratch = scratch_map[0]
    load QNAME bytes into scratch.qname (up to 256 bytes)

    walk labels (bounded loop, max 20 iterations):
        if label_len == 0 → end of QNAME
        if label_len >= 0xC0 → compression pointer, TC_ACT_OK (passthrough)
        if label_len > 63 → invalid, TC_ACT_OK
        record label boundary offset
        advance by 1 + label_len

    lowercase QNAME in scratch buffer (bounded loop, max 256)

    // --- Suffix matching ---
    for each label boundary (bounded loop, max 20):
        zero scratch.lookup
        copy suffix from that boundary into scratch.lookup
        if suffix_rules[scratch.lookup] exists → MATCH

    no match → TC_ACT_OK (passthrough to CoreDNS)

    // --- DNAT ---
    store conntrack: {pod_ip, pod_port, txid} → {coredns_ip, timestamp_ns=now}
    rewrite daddr: coredns_ip → host_resolver_ip
    fix IP checksum via bpf_l3_csum_replace
    fix UDP checksum via bpf_l4_csum_replace (BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0)
    TC_ACT_OK
```

**Key design choices:**
- `bpf_skb_load_bytes` for all reads (not direct packet access) — avoids pointer invalidation when `bpf_skb_store_bytes` is called later
- Compression pointers in QNAME → passthrough (technically legal per RFC 1035 but virtually never seen in question section)
- All error paths → `TC_ACT_OK` (never drop packets)
- Suffix matching: 3–7 hash map lookups per query (one per label boundary). Hash lookups are O(1).

### 6.3 Egress Program (TC egress on host-side veth)

Intercepts DNS responses from VPC DNS resolver going to pods. Restores source IP to CoreDNS so the pod sees a normal response.

```
dns_gateway_egress(skb):
    cfg = config_map[0]
    if !cfg → TC_ACT_OK
    // NOTE: egress does NOT check cfg.bypass — in-flight queries that were
    // DNAT'd before bypass flipped must still be SNAT'd back so the pod
    // never sees src=host_resolver_ip.

    load ETH, IP, UDP headers
    if saddr != cfg.host_resolver_ip → TC_ACT_OK
    if sport != 53 → TC_ACT_OK

    load DNS header (12 bytes); extract txid (bytes 0..1)
    ct = conntrack_map[{daddr, dport, txid}]
    if !ct → TC_ACT_OK (not our packet)

    // --- TTL check: defends against stale entries colliding with
    //     unrelated direct VPC-DNS responses ---
    if (now - ct.timestamp_ns) > CONNTRACK_TTL_NS:
        delete conntrack entry
        TC_ACT_OK (passthrough)

    // --- SNAT ---
    rewrite saddr: host_resolver_ip → ct.coredns_ip
    fix IP + UDP checksums
    delete conntrack entry
    TC_ACT_OK
```

`CONNTRACK_TTL_NS` defaults to 5 seconds — well past the typical DNS client retry window.

### 6.4 Suffix Matching Algorithm

DNS wire format encodes names as `(length, label)+, 0x00`. The key insight: the wire-format bytes from any label boundary to the end of the QNAME is itself a valid wire-format DNS name.

Example: `foo.s3.amazonaws.com`

```
Wire format: \x03foo\x02s3\x09amazonaws\x03com\x00

Label boundaries and lookup attempts:
  offset 0: \x03foo\x02s3\x09amazonaws\x03com\x00  (full name)
  offset 4: \x02s3\x09amazonaws\x03com\x00          ← matches suffix rule
  offset 7: \x09amazonaws\x03com\x00
  offset 17: \x03com\x00
```

Userspace populates `suffix_rules` map with wire-format keys. For a config rule `*.s3.amazonaws.com`:
1. Strip `*.` → `s3.amazonaws.com`
2. Encode to wire format: `\x02s3\x09amazonaws\x03com\x00`
3. Lowercase, zero-pad to 256 bytes
4. Store in hash map

**The encoding in userspace must be byte-identical to what the eBPF program extracts from packets.** A mismatch means silent matching failure.

### 6.5 Stack Usage Analysis

| On stack | Size | Notes |
|----------|------|-------|
| IP header (loaded) | 20 bytes | via `bpf_skb_load_bytes` |
| UDP header (loaded) | 8 bytes | |
| DNS header | 12 bytes | first 12 bytes |
| conntrack key/value | 24 bytes | |
| label offsets array | 80 bytes | `u32[20]` |
| loop counters, temps | ~40 bytes | |
| **Total** | **~184 bytes** | Well within 512-byte limit |

The 512-byte scratch buffer (QNAME + lookup) lives in the per-CPU map.

### 6.6 Metrics

| ID | Name | Description |
|----|------|-------------|
| 0 | `total_packets` | All packets seen on ingress |
| 1 | `dns_queries` | Packets identified as DNS queries to CoreDNS |
| 2 | `suffix_match` | Queries matched a suffix rule → DNAT'd |
| 3 | `suffix_no_match` | DNS queries to CoreDNS, no suffix match → passthrough |
| 4 | `bypass_active` | Packets passed through due to bypass flag |
| 5 | `parse_error` | DNS parse failures (compression ptr, malformed) |
| 6 | `egress_snat` | Response packets SNAT'd back |
| 7 | `egress_conntrack_miss` | Response from VPC DNS but no conntrack entry |
| 8 | `egress_total` | All packets seen on egress |

Per-CPU counters — userspace sums across CPUs for Prometheus export.

## 7. Controller Design (Go)

### 7.1 Responsibilities

```
Controller (systemd service)
├── Load eBPF programs (once)
├── Pin shared BPF maps to /sys/fs/bpf/dns-gateway/
├── Populate config_map from config file
├── Populate suffix_rules from config file
├── Subscribe to netlink RTM_NEWLINK/RTM_DELLINK
│   ├── On new veth → attach TC ingress + egress
│   └── On veth removal → cleanup tracking
├── Health-check VPC DNS resolver
│   └── On failure → set bypass flag in config_map
├── Export Prometheus metrics on :9153/metrics
└── Handle SIGTERM → set bypass → detach all → exit
```

### 7.2 Startup Sequence

```
1. Load config file (/etc/bpf-dns-gateway/config.yaml)
2. Load and verify eBPF programs (bpf2go generated)
3. Pin maps to /sys/fs/bpf/dns-gateway/
4. Populate config_map (CoreDNS IP, VPC resolver IP, port 53, bypass=0)
5. Populate suffix_rules from config
6. Start Prometheus metrics server (:9153)
7. Subscribe to netlink RTM_NEWLINK/RTM_DELLINK (events buffered while we reconcile)
8. Enumerate existing veths via netlink.LinkList(); attach eBPF
9. Drain buffered netlink events; for each new veth, dedup against the ifindex
   set populated in step 8 and attach if not already attached
10. Start health checker (periodic VPC DNS probes)
11. sd_notify(READY) → systemd considers service started

The subscribe-before-enumerate ordering with ifindex dedup closes the race where
a veth created between enumeration and listener startup would otherwise be missed.
```

### 7.3 Shutdown Sequence (SIGTERM)

```
1. Set bypass=1 in config_map (ingress stops new DNAT immediately; egress continues to SNAT in-flight responses until conntrack drains)
2. Stop netlink listener
3. Detach eBPF from all veths
4. Unpin maps from /sys/fs/bpf/
5. Close eBPF program fds
6. Exit
```

### 7.4 Crash Safety

MVP uses **TCX only** (kernel 6.6+ required). TCX programs are owned by the controller's link fds — when the process exits for any reason, the kernel auto-detaches the programs from every veth. DNS immediately falls back to CoreDNS.

This preserves the §2 "every failure mode falls back to CoreDNS" invariant without any orphan-cleanup logic. Classic TC fallback is intentionally out of scope for MVP.

### 7.5 Health Checker

Periodically sends a DNS A query (e.g., for `amazon.com`) to the VPC resolver. If N consecutive probes fail (default: 3), sets the `bypass` flag in `config_map`. When probes recover, clears the flag.

```
probe interval:  5 seconds
probe timeout:   2 seconds
failure threshold: 3 consecutive failures → bypass ON
recovery threshold: 1 success → bypass OFF
```

When bypass is active, **only the ingress program** short-circuits to `TC_ACT_OK` — no new queries are DNAT'd. The egress program intentionally ignores `bypass`: any in-flight query that was already DNAT'd to VPC DNS before bypass flipped will produce a response from VPC DNS, and that response must still be SNAT'd back to CoreDNS so the pod never sees `src=host_resolver_ip`. Once the conntrack table drains naturally (via TTL or LRU), egress traffic stops being touched and the system is fully passthrough.

This asymmetry also covers graceful shutdown: setting bypass before detach lets in-flight queries complete cleanly.

## 8. Configuration

```yaml
# /etc/bpf-dns-gateway/config.yaml

# CoreDNS ClusterIP — from EKS cluster configuration
# (10.100.0.10 for 10.100.0.0/16 service CIDR, 172.20.0.10 for 172.20.0.0/16)
corednsServiceIP: "10.100.0.10"

# VPC DNS resolver — REQUIRED. On EKS this is the VPC CIDR base +2
# (e.g., 10.0.0.2 for a 10.0.0.0/16 VPC). Auto-detection is intentionally
# not supported: nodes running systemd-resolved expose 127.0.0.53 in
# /etc/resolv.conf, which is a loopback stub and cannot serve DNAT'd
# pod traffic.
hostResolverIP: "10.0.0.2"

# Suffix rules — any matching suffix triggers redirect; rules are not ordered.
# Only suffix wildcards (*.domain) are supported in MVP.
# Interior wildcards (*.s3.*.amazonaws.com) must be expanded to explicit suffixes.
rules:
  - pattern: "*.s3.amazonaws.com"
    action: host-resolve
  - pattern: "*.s3.us-east-1.amazonaws.com"
    action: host-resolve
  - pattern: "*.s3.us-west-2.amazonaws.com"
    action: host-resolve
  - pattern: "*.dkr.ecr.us-east-1.amazonaws.com"
    action: host-resolve
  - pattern: "*.sts.us-east-1.amazonaws.com"
    action: host-resolve

# Prometheus metrics
metricsAddr: ":9153"

# Health check
healthCheck:
  interval: 5s
  timeout: 2s
  failureThreshold: 3

# Logging
logLevel: info
```

### 8.1 Pattern Semantics

- `*.s3.amazonaws.com` → matches any name ending in `.s3.amazonaws.com`
- Implemented as suffix match: strip `*.`, encode the remainder to wire format
- Patterns must use the `*.` prefix in MVP. Exact-only matching is not supported because the suffix hash map cannot distinguish an exact name from a wildcard with the same suffix at any label boundary. Loader rejects patterns without `*.`
- Interior wildcards NOT supported in the eBPF path — expand at config time

## 9. Edge Cases

### 9.1 DNS Protocol Edge Cases

| Case | Behavior |
|------|----------|
| DNS compression pointers in QNAME | Passthrough to CoreDNS (increment `parse_error` metric) |
| EDNS0 OPT records | Not affected — in ADDITIONAL section, not parsed. DNS payload passes through unmodified. |
| QDCOUNT = 0 | Passthrough |
| QDCOUNT > 1 | Passthrough (intent ambiguous — first-Q match could misroute later cluster-local Qs). Increments `parse_error` metric. |
| IP-fragmented query | Ingress passthrough — UDP+DNS headers may be split across fragments. Original query still reaches CoreDNS; correct. |
| IP-fragmented response from VPC DNS | **Known limitation**: egress passes fragments through unchanged, so the pod sees `src=host_resolver_ip` on the reassembled response. AWS service DNS responses (S3/ECR/STS) are far below MTU in practice and never fragment. DNSSEC-enabled or EDNS0-bloated responses could trigger this. Mitigated client-side by retry-over-TCP (which bypasses our eBPF). Post-MVP fix: track IP-ID conntrack or set DF bit on DNAT'd queries to force TC-bit truncation. |
| BPF helper failure (`bpf_map_update_elem`) | Ingress checks return; on failure passes through (no orphan DNAT). |
| BPF helper failure (`bpf_skb_store_bytes`, `bpf_l3_csum_replace`, `bpf_l4_csum_replace`) | Return values not checked. These helpers do not allocate and only fail on pathological offsets; in practice they always succeed when their static offsets are valid. **Known correctness gap** — on theoretical failure, packet may be partially rewritten and conntrack state may diverge from packet state. Acceptable for MVP; add checks if any failure observed via verifier or production telemetry. |
| QNAME wire-format > 128 bytes | Passthrough — `MAX_DNS_NAME_LEN` is 128 in MVP. AWS service DNS names are well under (typical 40-80 bytes). Cut from 256 to keep the BPF verifier under its 1M instruction limit. |
| Mixed-case or uppercase QNAME | Misses suffix rules and falls through to CoreDNS. **Known MVP limitation**: case normalization is not performed in the BPF program because the lowercase loop interacts with the unrolled suffix-copy loop and exhausts the verifier instruction limit. Real-world DNS clients (glibc, musl, AWS SDKs) emit lowercase. Servers using DNS 0x20-bit randomization (RFC 7873) bypass our optimization but still get correct DNS resolution via CoreDNS. Fixable post-MVP via `bpf_loop()` helper. |
| Malformed packets | All parse failures → TC_ACT_OK (never drop) |
| TCP DNS | Not matched (`protocol != UDP`) → goes to CoreDNS directly |
| DNS-over-HTTPS / DNS-over-TLS | Different ports (443, 853) — not intercepted |
| UDP checksum = 0 | `BPF_F_MARK_MANGLED_0` flag handles correctly |
| DNS response truncation (TC bit) | Passed through as-is. Client retries over TCP, which bypasses eBPF. |

### 9.2 Infrastructure Edge Cases

| Case | Behavior |
|------|----------|
| VPC DNS resolver down | Health checker sets bypass → all DNS goes to CoreDNS |
| Controller crash | TCX programs auto-detach when fds close → DNS falls back to CoreDNS |
| Pod with dnsPolicy: None | Pod sends DNS to arbitrary server, not CoreDNS IP → not matched |
| HostNetwork pods | No veth — not intercepted |
| Same-node CoreDNS pod | CoreDNS pod's DNS goes through its own veth → matched and redirected (correct behavior) |
| Veth created before controller starts | Startup reconciliation attaches to all existing veths |
| ndots search expansion | Each expanded query (e.g., `svc.ns.svc.cluster.local`) is matched individually against suffixes. AWS suffixes won't match cluster-local expansions — correct. |

## 10. Observability

### 10.1 Prometheus Metrics

```
# eBPF datapath counters (from per-CPU maps, summed)
bpf_dns_gateway_ingress_total_packets
bpf_dns_gateway_dns_queries_total
bpf_dns_gateway_suffix_match_total
bpf_dns_gateway_suffix_no_match_total
bpf_dns_gateway_bypass_packets_total
bpf_dns_gateway_parse_errors_total
bpf_dns_gateway_egress_snat_total
bpf_dns_gateway_egress_conntrack_miss_total
bpf_dns_gateway_egress_total_packets

# Controller metrics
bpf_dns_gateway_attached_veths          (gauge)
bpf_dns_gateway_health_check_failures   (counter)
bpf_dns_gateway_bypass_active           (gauge, 0 or 1)
bpf_dns_gateway_suffix_rules_loaded     (gauge)
```

### 10.2 Logging

Structured logging (Go `slog`) with levels:
- **INFO**: veth attach/detach, bypass state changes, startup/shutdown
- **WARN**: health check failures
- **ERROR**: eBPF load/attach failures, config parse errors

### 10.3 Recommended Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| BPFDNSGatewayBypassActive | `bypass_active == 1` for > 1 min | Warning |
| BPFDNSGatewayHighParseErrors | `parse_errors_total` rate > 10/s | Warning |
| BPFDNSGatewayDown | systemd unit not active | Critical |
| BPFDNSGatewayNoVeths | `attached_veths == 0` for > 5 min on a node with pods | Warning |

## 11. Constraints and Limitations

1. **Routable pod IPs required** — DNAT'd packets (`src=pod_ip, dst=vpc_dns`) must be routable from the VPC DNS resolver. Works with EKS VPC CNI (pod IPs are VPC secondary IPs). May not work with overlay CNIs.
2. **Kernel 6.6+** — required for TCX attach mode (`link.AttachTCX`) so programs auto-detach on controller crash. Classic TC fallback is intentionally out of scope for MVP (would reintroduce orphaned-program risk).
3. **IPv4 only** — IPv6 support can be added in a future version.
4. **UDP DNS only** — TCP DNS (used for zone transfers and large responses) bypasses eBPF and goes to CoreDNS. This is correct behavior.
5. **Suffix wildcards only** — interior wildcards (`*.s3.*.amazonaws.com`) must be expanded to explicit per-region suffixes.
6. **Single host resolver IP** — the config supports one VPC DNS resolver IP. On EKS this is the VPC CIDR base +2 and is stable.
7. **QNAME ≤ 128 wire bytes and ≤ `MAX_LABELS` (10) labels** — longer names pass through to CoreDNS. The label bound is deliberately conservative (AWS service names have ≤7 labels) because the suffix-match loops drive BPF verifier state: `MAX_LABELS=20` loaded on kernel 6.12 but **exhausted the verifier's 1M-instruction limit on kernel 6.18**. `MAX_LABELS=10` loads on both. A verifier-independent rewrite (`bpf_loop()`) is the durable fix — tracked as future work.

## 12. Project Structure

```
bpf-dns-gateway/
├── cmd/
│   └── bpf-dns-gateway/
│       └── main.go                     # Entry point, signal handling, sd_notify
├── internal/
│   ├── controller/
│   │   └── controller.go               # Top-level orchestration
│   ├── netlinkmon/
│   │   └── monitor.go                  # Netlink veth event subscription
│   ├── vethlink/
│   │   └── link.go                     # Veth detection and interface ops
│   ├── ebpf/
│   │   ├── loader.go                   # bpf2go codegen, program loading, map pinning
│   │   ├── attach.go                   # TCX attach (kernel 6.6+)
│   │   └── maps.go                     # Map CRUD: suffix rules, config, metrics read
│   ├── dnsenc/
│   │   └── wire.go                     # DNS wire-format encoding for suffix keys
│   ├── health/
│   │   └── checker.go                  # Periodic VPC DNS probe, bypass flag toggle
│   ├── metrics/
│   │   └── collector.go                # Prometheus collector from per-CPU counters
│   └── config/
│       └── config.go                   # Config file parsing, validation, defaults
├── bpf/
│   ├── dns_gateway.c                   # eBPF programs (ingress + egress)
│   ├── dns_gateway.h                   # Map/struct definitions, constants
│   └── headers/                        # vmlinux.h, bpf_helpers.h, bpf_endian.h
├── deploy/
│   ├── bpf-dns-gateway.service         # systemd unit file
│   └── config.yaml                     # Example config
├── test/
│   ├── integration/
│   │   └── redirect_test.go            # Network namespace + veth + eBPF tests
│   └── e2e/
│       └── e2e_test.go                 # Kind or EC2-based tests
├── docs/
│   └── design.md                       # This document
├── Makefile
├── Dockerfile                          # For CI/build (not runtime)
├── go.mod
└── README.md
```

## 13. Implementation Phases

### Phase 1: eBPF Core + Scaffold
- Project scaffolding: `go.mod`, `Makefile`, bpf2go pipeline
- `bpf/dns_gateway.h` — all map and struct definitions
- `bpf/dns_gateway.c` — ingress (DNS parse + suffix match + DNAT) and egress (SNAT)
- `internal/ebpf/loader.go` — load programs, pin maps
- `internal/dnsenc/wire.go` — DNS wire-format encoding
- **Milestone**: manually attach to a veth, verify DNAT/SNAT with `dig` from a network namespace

### Phase 2: Controller + Netlink
- `internal/netlinkmon/monitor.go` — netlink veth event subscription
- `internal/vethlink/link.go` — veth identification
- `internal/ebpf/attach.go` — TCX attach (kernel 6.6+)
- `internal/ebpf/maps.go` — suffix rule and config map population
- `internal/config/config.go` — config file parsing
- `cmd/bpf-dns-gateway/main.go` — startup/shutdown orchestration
- **Milestone**: binary that auto-attaches eBPF to veths as pods are created

### Phase 3: Reliability + Observability
- `internal/health/checker.go` — VPC DNS health probe, bypass flag
- `internal/metrics/collector.go` — Prometheus from per-CPU counters
- Graceful shutdown (set bypass → detach → exit)
- Startup reconciliation (subscribe netlink, enumerate existing veths, dedup by ifindex)
- Structured logging
- **Milestone**: production-grade systemd service with metrics and health checks

### Phase 4: Testing + Packaging
- Unit tests: DNS encoding, config parsing, metric aggregation
- Integration tests: network namespace + veth pair + eBPF + raw DNS packets
- `deploy/bpf-dns-gateway.service` — systemd unit
- `deploy/config.yaml` — example config
- AMI build integration (packer or similar)
- **Milestone**: installable package with tested end-to-end flow

## 14. Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| `github.com/cilium/ebpf` | v0.17+ | eBPF loading, bpf2go codegen, TCX/TC attach, map ops |
| `github.com/vishvananda/netlink` | v1.3+ | Netlink subscription and veth discovery |
| `github.com/prometheus/client_golang` | v1.20+ | Prometheus metrics |
| `github.com/miekg/dns` | v1.1+ | DNS message construction for health check probes |
| `log/slog` | stdlib | Structured logging |

No Kubernetes client libraries. No container runtime dependencies.
