# BPF DNS Gateway — Task List

Ordered implementation tasks with dependencies. Integration tests are interleaved after each layer to validate before building the next.

## Phase 1: eBPF Core + Scaffold

### 1. ✅ Project scaffolding
Initialize `go.mod`, directory structure (`cmd/`, `internal/`, `bpf/`, `deploy/`, `test/`, `docs/`), `Makefile` with `generate`/`build`/`test`/`clean` targets, and bpf2go code generation pipeline. Verify an empty eBPF program compiles.

- **Blocked by**: nothing (first task)
- **Files**: `go.mod`, `Makefile`, directory tree

### 2. ✅ BPF header and map definitions
Write `bpf/dns_gateway.h` with all struct/map definitions: `suffix_rules` (HASH), `config_map` (ARRAY), `conntrack_map` (LRU_HASH), `metrics_map` (PERCPU_ARRAY), `scratch_map` (PERCPU_ARRAY). Include constants (`MAX_DNS_NAME_LEN=256`, `MAX_LABELS=20`, `CONNTRACK_TTL_NS` (default 5s), metric IDs, `ACTION_HOST_RESOLVE`). `conntrack_key` includes `{pod_ip, pod_port, txid}`; `conntrack_value` includes `{coredns_ip, timestamp_ns}`.

- **Blocked by**: #1
- **Files**: `bpf/dns_gateway.h`

### 3. ✅ eBPF ingress program (DNS parse + suffix match + DNAT)
Write `dns_gateway_ingress` in `bpf/dns_gateway.c`: ETH/IP/UDP parsing via `bpf_skb_load_bytes`, DNS header validation (QR=0, **QDCOUNT==1** — multi-question or zero-question packets pass through with `parse_error` metric), extract `txid` from DNS hdr, QNAME extraction into scratch buffer, label walking (bounded loop max 20), lowercase normalization, suffix matching via hash map lookups at each label boundary, conntrack creation with key `{pod_ip, pod_port, txid}` and value `{coredns_ip, timestamp_ns=ktime_get_ns()}`, DNAT with L3/L4 checksum fixup (`BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0`). All error paths return `TC_ACT_OK`.

- **Blocked by**: #2
- **Files**: `bpf/dns_gateway.c`

### 4. ✅ eBPF egress program (conntrack SNAT)
Write `dns_gateway_egress` in `bpf/dns_gateway.c`: match `src=host_resolver_ip` and `sport=53`, extract `txid` from DNS hdr, conntrack lookup by `{daddr, dport, txid}`, **TTL check**: if `ktime_get_ns() - timestamp_ns > CONNTRACK_TTL_NS` → delete entry + passthrough; else SNAT src back to CoreDNS IP, checksum fixup, delete conntrack entry. **Egress does NOT check `cfg->bypass`** — in-flight DNAT'd queries must drain. All error paths return `TC_ACT_OK`.

- **Blocked by**: #2
- **Files**: `bpf/dns_gateway.c`

### 5. ✅ DNS wire-format encoding + unit tests
Implement `EncodeSuffix`: domain string → `[256]byte` wire-format key (lowercase, zero-padded). Must be byte-identical to what the eBPF program extracts from packets. Also implement `DecodeSuffix` for debugging/tests. Unit tests covering: normal domains, max-length labels, multi-label, single label, case normalization, edge cases (empty, trailing dot).

- **Blocked by**: #1
- **Files**: `internal/dnsenc/wire.go`, `internal/dnsenc/wire_test.go`

### 6. ✅ eBPF loader and map management
Implement loader: bpf2go `go:generate` directive, `LoadPrograms()` to load compiled eBPF objects, pin maps to `/sys/fs/bpf/dns-gateway/`. Implement map ops: `PopulateConfig` (write `config_map` entry), `PopulateSuffixRules` (encode patterns, write/delete hash map entries with full reconciliation), `ReadMetrics` (sum per-CPU counters). Unit tests for map operations.

- **Blocked by**: #3, #4, #5
- **Files**: `internal/ebpf/loader.go`, `internal/ebpf/maps.go`, `internal/ebpf/maps_test.go`

### 7. ✅ TCX attach/detach
Implement `AttachToInterface` using TCX only (`link.AttachTCX` on kernel 6.6+), `DetachFromInterface`. Track attached interfaces (ifindex → links). On controller crash TCX auto-detaches when fds close — no orphan cleanup needed. Unit tests with dummy veth pairs. (Classic TC fallback and VPC CNI coexistence are post-MVP — see `docs/vpc-cni-coexistence.md`.)

- **Blocked by**: #6
- **Files**: `internal/ebpf/attach.go`, `internal/ebpf/attach_test.go`

### 8. ✅ Integration test: eBPF DNAT/SNAT (BPF_PROG_TEST_RUN)
Set up a network namespace + veth pair, attach eBPF programs, populate suffix rules and config maps, send a raw DNS UDP query from the namespace for a matching domain, verify DNAT occurred (dst rewritten to host resolver). Send a crafted response from host resolver IP, verify SNAT (src rewritten to CoreDNS IP). Also test passthrough for non-matching domains. **This validates the full eBPF datapath before building the controller.**

- **Blocked by**: #7
- **Files**: `test/integration/redirect_test.go`

## Phase 2: Controller + Netlink

### 9. ✅ Config file parsing + unit tests
Parse YAML config file with fields: `corednsServiceIP` (required), `hostResolverIP` (**required** — no auto-detect; systemd-resolved nodes expose `127.0.0.53` which is a loopback stub and must not be used), `rules` (pattern + action), `metricsAddr`, `healthCheck` (interval, timeout, failureThreshold), `logLevel`. Validation: valid IPs (reject loopback for `hostResolverIP`), valid patterns (must use `*.suffix` form — reject exact patterns and interior wildcards), port ranges.

- **Blocked by**: #1
- **Files**: `internal/config/config.go`, `internal/config/config_test.go`

### 10. ✅ Netlink veth monitor
Subscribe to `RTNLGRP_LINK` via netlink socket, filter for `RTM_NEWLINK`/`RTM_DELLINK` events, identify veth interfaces (check `IFLA_INFO_KIND == "veth"`), expose a channel or callback interface for new/removed veths. On startup, enumerate all existing veths via `netlink.LinkList()`. Unit tests with real veth creation in a test namespace.

- **Blocked by**: #1
- **Files**: `internal/netlinkmon/monitor.go`, `internal/netlinkmon/monitor_test.go`

### 11. ✅ Controller orchestration
Ties together netlink monitor, eBPF loader, attach/detach, map management. On new veth → attach ingress + egress. On veth removal → cleanup tracking. Tracks attached interfaces in `map[int]AttachmentInfo` (ifindex → links). **Startup ordering**: subscribe netlink first, then enumerate existing veths via `netlink.LinkList()`, dedup against the ifindex set so a veth created between subscribe and enumerate is not double-attached or missed. Exposes methods for shutdown (detach all) and bypass toggle.

- **Blocked by**: #7, #9, #10
- **Files**: `internal/controller/controller.go`

### 12. ✅ Integration test: full controller with veth lifecycle
Start controller, create a veth pair, verify eBPF auto-attaches. Send DNS query for matching domain, verify redirect. Send DNS query for non-matching domain, verify passthrough. Delete veth, verify cleanup. Test startup reconciliation: create veth before controller starts, verify it gets picked up.

- **Blocked by**: #11
- **Files**: `test/integration/controller_test.go`

## Phase 3: Reliability + Observability

### 13. ✅ Health checker
Periodic DNS A query probe to the VPC resolver (configurable interval/timeout). On N consecutive failures (configurable threshold), set `bypass=1` in `config_map`. On recovery (1 success), clear bypass. Uses `miekg/dns` for probe construction. Unit tests with mock DNS server.

- **Blocked by**: #6
- **Files**: `internal/health/checker.go`, `internal/health/checker_test.go`

### 14. Prometheus metrics collector
Prometheus `Collector` interface that reads per-CPU counters from `metrics_map`, sums across CPUs, exposes as `bpf_dns_gateway_*` counters. Also expose controller gauges: `attached_veths`, `bypass_active`, `suffix_rules_loaded`, `health_check_failures` counter.

- **Blocked by**: #6
- **Files**: `internal/metrics/collector.go`, `internal/metrics/collector_test.go`

### 15. Main entrypoint and lifecycle
Parse CLI flags (`--config`), load config, initialize `slog` logger, start metrics server, load eBPF + pin maps, populate config/rules, start controller (netlink + attach), start health checker, `sd_notify(READY)`. Signal handling: SIGTERM/SIGINT → set bypass flag → detach all → unpin maps → exit. Ordered startup and shutdown per design doc.

- **Blocked by**: #11, #13, #14
- **Files**: `cmd/bpf-dns-gateway/main.go`

### 16. Integration test: bypass mode and health checker
Set bypass flag, verify new DNS queries pass through unmodified (no ingress DNAT). **Verify in-flight queries already DNAT'd before bypass flipped still get SNAT'd correctly on egress** (egress does not honor bypass). Start health checker with unreachable resolver, verify bypass activates after threshold. Restore resolver, verify bypass clears. Test graceful shutdown: verify bypass set before detach. Verify conntrack TTL: stale entry past `CONNTRACK_TTL_NS` is deleted on egress and packet passes through.

- **Blocked by**: #12, #13, #15
- **Files**: `test/integration/bypass_test.go`

### 17. Integration test: edge cases
DNS edge cases: compression pointer in QNAME (passthrough + `parse_error` metric), QDCOUNT=0 (passthrough), **QDCOUNT>1 (passthrough + `parse_error`)**, malformed packet with `label_len > 63` (passthrough), TCP DNS on port 53 (passthrough, `protocol != UDP`), UDP checksum=0 packet, max-length QNAME (>128 wire bytes → passthrough), **QNAME with many short labels (>20)** — passthrough since exceeds `MAX_LABELS`, **query with uppercase letters → passthrough to CoreDNS** (BPF-side lowercasing was dropped for verifier budget; mixed/upper-case misses suffix rules — known limitation, `design.md §9.1`), **concurrent A+AAAA from same source port** with different txids — both responses correctly SNAT'd.

- **Blocked by**: #8
- **Files**: `test/integration/edge_cases_test.go`

## Phase 4: Packaging

### 18. Systemd unit file and example config
Write `deploy/bpf-dns-gateway.service` (`Type=notify`, `After=network.target`, `Before=kubelet.service`, `LimitMEMLOCK=infinity`, `Restart=always`). Write `deploy/config.yaml` with example S3/ECR/STS rules and inline comments.

- **Blocked by**: #15
- **Files**: `deploy/bpf-dns-gateway.service`, `deploy/config.yaml`

### 19. Dockerfile for CI builds
Multi-stage Dockerfile: stage 1 (clang + llvm + Go) compiles eBPF C and builds Go binary with bpf2go. Stage 2 minimal image with just the binary. Not used at runtime (binary goes into AMI), but needed for CI and reproducible builds.

- **Blocked by**: #15
- **Files**: `Dockerfile`

### 20. README and CLAUDE.md
Write `README.md`: project overview, architecture diagram, quick start (build, configure, install), configuration reference, metrics reference. Write `CLAUDE.md` with build instructions, test commands, project structure, and key conventions for development.

- **Blocked by**: #15
- **Files**: `README.md`, `CLAUDE.md`

## Dependency Graph

```
#1 Project scaffolding
├── #2 BPF headers ──→ #3 Ingress program ──┐
│                  └──→ #4 Egress program  ──┤
├── #5 DNS wire encoding ────────────────────┤
├── #9 Config parsing ──────────────────┐    │
└── #10 Netlink monitor ────────────┐   │    │
                                    │   │    │
                       #6 eBPF loader + maps ◄┘
                                    │   │    │
                       #7 TCX attach/detach
                       │    │       │   │
          #8 🧪 DNAT/SNAT test     │   │
          │                         │   │
          #17 🧪 Edge cases         │   │
                                    │   │
               #13 Health ◄─────────┤   │
               #14 Metrics ◄────────┘   │
                   │                    │
               #11 Controller ◄─────────┘
                   │
          #12 🧪 Controller test
                   │
               #15 Main entrypoint
                   │
          #16 🧪 Bypass + shutdown test
                   │
               ├── #18 Systemd unit
               ├── #19 Dockerfile
               └── #20 README
```
