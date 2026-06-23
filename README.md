# bpf-dns-gateway

Transparently route selected pod DNS queries on EKS straight to the VPC DNS
resolver, bypassing the CoreDNS hop — without pods noticing.

eBPF TC programs on each pod's host-side veth intercept DNS queries headed to
CoreDNS. Queries whose name matches a configured suffix (e.g.
`*.s3.amazonaws.com`) are DNAT'd to the VPC resolver; the response is SNAT'd
back so the pod sees an answer that appears to come from CoreDNS. Everything
else passes through untouched. Any failure falls back to CoreDNS — the
datapath never drops a packet.

## Why

For AWS service endpoints (S3, ECR, STS, …) CoreDNS just forwards to the VPC
resolver anyway. Skipping the hop cuts latency, offloads CoreDNS, and keeps
topology-aware answers (e.g. S3) optimized for the pod's node instead of
CoreDNS's location.

## Architecture

```
            Pod netns                         Host netns
        ┌───────────────┐
        │ DNS query      │   veth      ┌──────────────────────────────┐
        │ dst=CoreDNS:53 │────────────▶│ TC ingress (host-side veth)  │
        └───────────────┘             │  parse ETH/IP/UDP/DNS         │
                                       │  suffix match (hash map)      │
                                       │   match → DNAT dst=VPC DNS    │
                                       │   + conntrack {pod,port,txid} │
                                       │   no match / error → CoreDNS  │
                                       └───────────────┬──────────────┘
                                                       │ kernel routing
                                          matched ─────┴──▶ VPC DNS resolver
                                                       │
                                       ┌───────────────▼──────────────┐
                                       │ TC egress (host-side veth)    │
                                       │  src=VPC DNS + conntrack hit  │
                                       │   → SNAT src=CoreDNS          │
                                       │   (stale/expired → passthrough)│
                                       └───────────────┬──────────────┘
                                                       │
        ┌───────────────┐                              │
        │ pod sees       │◀─────────────────────────────┘
        │ src=CoreDNS:53 │   (transparent)
        └───────────────┘
```

A small Go controller loads the eBPF programs, populates the rule/config BPF
maps, watches netlink for veths and attaches via TCX, health-checks the VPC
resolver (flipping a bypass flag when it's unhealthy), and exports Prometheus
metrics.

See [`docs/design.md`](docs/design.md) for the full spec and
[`docs/example-walkthrough.md`](docs/example-walkthrough.md) for a packet trace.

## Requirements

- **Linux kernel 6.6+** (TCX attach; programs auto-detach when the controller
  exits). x86_64.
- **EKS with VPC CNI** — pod IPs must be routable from the VPC resolver
  (DNAT'd packets keep the pod source IP). Overlay CNIs are not supported.
- bpffs mounted at `/sys/fs/bpf`.

## Build

```
make build      # generate eBPF (bpf2go) + go build → bin/bpf-dns-gateway
make test       # go test ./...
make vet
make generate   # regenerate internal/ebpf/*_bpfel.{go,o} from bpf/dns_gateway.c
```

Container image (CI / DaemonSet):

```
docker build -t <registry>/bpf-dns-gateway:<tag> .
```

## Configure

Edit [`deploy/config.yaml`](deploy/config.yaml):

```yaml
corednsServiceIP: "10.100.0.10"      # kube-dns ClusterIP
hostResolverIP:   "169.254.169.253"  # REQUIRED — VPC resolver (base+2 or link-local)
rules:
  - { pattern: "*.s3.amazonaws.com",            action: host-resolve }
  - { pattern: "*.dkr.ecr.us-west-2.amazonaws.com", action: host-resolve }
metricsAddr: ":9153"
healthCheck: { interval: 5s, timeout: 2s, failureThreshold: 3 }
logLevel: info
```

- `hostResolverIP` is **required** — no `/etc/resolv.conf` auto-detect
  (systemd-resolved nodes expose the `127.0.0.53` loopback stub, which can't
  serve DNAT'd traffic).
- Patterns are **leading-wildcard suffixes only** (`*.suffix`). Exact and
  interior wildcards are rejected. Matching is case-sensitive (resolvers emit
  lowercase; mixed-case falls through to CoreDNS).
- Rules are unordered; any match redirects.

## Deploy

### Option A — systemd (recommended)

Bake the binary + unit into the node AMI so it starts before kubelet.

```
install -m0755 bin/bpf-dns-gateway /usr/local/bin/
install -d /etc/bpf-dns-gateway
install -m0644 deploy/config.yaml /etc/bpf-dns-gateway/config.yaml   # edit first
install -m0644 deploy/bpf-dns-gateway.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now bpf-dns-gateway
```

No Kubernetes API dependency at runtime; survives kubelet restarts.

### Option B — DaemonSet (optional)

K8s-native rollout for clusters that prefer it. Trades away start-before-kubelet
and adds a K8s-API dependency at rollout time — see
[`docs/audit/001-daemonset-deployment.md`](docs/audit/001-daemonset-deployment.md).

```
# edit the image ref in deploy/daemonset.yaml + config in deploy/configmap.yaml
kubectl apply -f deploy/configmap.yaml
kubectl apply -f deploy/daemonset.yaml
```

Privileged, hostPID/hostNetwork, `/sys/fs/bpf` bind-mounted, linux/amd64 nodes
only. Config changes require a rollout (`kubectl -n kube-system rollout restart
ds/bpf-dns-gateway`) — the binary reads config once at startup.

## Observability

Prometheus metrics + `/healthz` on `metricsAddr` (default `:9153`).

| Metric | Type | Meaning |
|--------|------|---------|
| `bpf_dns_gateway_ingress_total_packets` | counter | All packets on TC ingress |
| `bpf_dns_gateway_dns_queries_total` | counter | DNS queries to CoreDNS seen |
| `bpf_dns_gateway_suffix_match_total` | counter | Queries matched a rule → DNAT'd |
| `bpf_dns_gateway_suffix_no_match_total` | counter | Queries with no match → passthrough |
| `bpf_dns_gateway_bypass_packets_total` | counter | Packets passed through due to bypass |
| `bpf_dns_gateway_parse_errors_total` | counter | DNS parse failures / QDCOUNT≠1 / compression ptr |
| `bpf_dns_gateway_egress_snat_total` | counter | Responses SNAT'd back to CoreDNS |
| `bpf_dns_gateway_egress_conntrack_miss_total` | counter | VPC-DNS responses with no/expired conntrack |
| `bpf_dns_gateway_egress_total_packets` | counter | All packets on TC egress |
| `bpf_dns_gateway_attached_veths` | gauge | Interfaces currently attached |
| `bpf_dns_gateway_bypass_active` | gauge | 1 if bypass on, else 0 |
| `bpf_dns_gateway_suffix_rules_loaded` | gauge | Rules in the BPF map |
| `bpf_dns_gateway_health_check_failures` | counter | Failed VPC DNS probes |
| `bpf_dns_gateway_scrape_errors_total` | counter | BPF-map read errors during a scrape |

## How it stays safe

- **Errors → passthrough.** Parse/validation error paths in eBPF return
  `TC_ACT_OK`, so a malformed or unmatched query degrades to "DNS via CoreDNS".
  (One known gap: the NAT/checksum helper return values are not checked after
  conntrack insertion — a helper failure could leave a packet partially
  rewritten rather than cleanly passed through. See `docs/design.md` §9.1.)
- **Health bypass.** If the VPC resolver fails N consecutive probes the
  controller sets a bypass flag and all DNS goes to CoreDNS until it recovers.
- **Crash-safe.** TCX programs auto-detach when the controller process exits.
- **conntrack** is keyed `{pod_ip, pod_port, txid}` (so concurrent A+AAAA don't
  collide) and TTL-checked on egress (stale entries are deleted and the packet
  passes through unmodified — never SNAT'd against a stale mapping).

## Limitations (MVP)

IPv4 + UDP only · x86_64 / kernel 6.6+ · suffix wildcards only ·
case-sensitive matching · QNAME ≤128 wire bytes · VPC CNI network-policy
coexistence is post-MVP ([`docs/vpc-cni-coexistence.md`](docs/vpc-cni-coexistence.md)).

## Development

Scale benchmark (1000-pod S3 DNS IP diversity + latency, with vs without):
[`docs/benchmark-diversity.md`](docs/benchmark-diversity.md).

End-to-end live validation on EKS (S3 workload, CoreDNS-vs-VPC-resolver proof):
[`docs/testing.md`](docs/testing.md).

See [`CLAUDE.md`](CLAUDE.md) for the build/test commands, the phase-by-phase
workflow, the EKS live-test method, and key datapath conventions. Design docs
live in [`docs/`](docs/).
