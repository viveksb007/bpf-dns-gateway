# CLAUDE.md — bpf-dns-gateway

eBPF TC programs intercept pod DNS queries on EKS. Match suffixes (e.g. `*.s3.amazonaws.com`) → DNAT to VPC DNS resolver, bypassing CoreDNS. Egress SNAT restores src so pods see response from CoreDNS (transparent). Runs as systemd service, not DaemonSet.

## Build / Test Commands

```
make generate   # bpf2go: regenerate internal/ebpf/dnsgateway_x86_bpfel.{go,o} from bpf/dns_gateway.c
make build      # generate + go build to bin/bpf-dns-gateway
make test       # go test ./...
make vet        # go vet ./...
make vmlinux    # regenerate bpf/headers/vmlinux.h from running kernel
make clean      # remove bin/ and generated .go/.o
```

Module path: `github.com/viveksb007/bpf-dns-gateway`. Go 1.25, Cilium ebpf v0.21.

## Project Structure

```
cmd/bpf-dns-gateway/main.go    Entry point, signal handling, sd_notify
internal/
  config/                      Config YAML parser + validation
  controller/                  Top-level orchestration
  netlinkmon/                  RTM_NEWLINK/RTM_DELLINK subscription
  vethlink/                    Veth detection
  ebpf/                        bpf2go generated + loader.go + attach.go + maps.go
  dnsenc/                      DNS wire-format encoding (suffix keys)
  health/                      Periodic VPC DNS probe + bypass toggle
  metrics/                     Prometheus collector from per-CPU counters
bpf/
  dns_gateway.{c,h}            eBPF TC ingress + egress programs
  headers/                     vmlinux.h, bpf_helpers.h, bpf_endian.h
deploy/                        systemd unit + example config.yaml
test/{integration,e2e}/        Network-namespace and EKS tests
docs/                          design.md, tasks.md, example-walkthrough.md, vpc-cni-coexistence.md
```

## Implementation Process

For each task in `docs/tasks.md`, follow this loop:

1. **Implement one task end-to-end.** Code + unit tests in the same change.
2. **Test on live EKS cluster** when feasible.
   - Cluster: `viveksbh-Isengard@example-cluster.us-west-2.eksctl.io` (already in current kubectx).
   - For BPF datapath tasks, prefer testing in a network namespace on a node first (cheaper), then on a cluster pod.
   - For controller tasks, run the binary on a node (via `kubectl debug node/<name>` or SSH) and exercise pod create/delete.
   - If a task is not testable live (e.g. DNS wire encoding unit logic), say so explicitly.
3. **Get review from Codex.** Run `codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox "<review prompt>"`. Pass the diff and the test results. Ask for severity-ranked findings.
4. **Address Codex findings.** Apply fixes. If you and Codex disagree on a finding, **stop and loop the user in** with both sides of the argument before applying or dismissing.
5. **Mark task complete in `docs/tasks.md`** (✅ next to the task heading) only after Codex review passes with no outstanding BLOCKER/MAJOR.
6. **Commit after each task.** One commit per task (or per paired task batch) so review history aligns with task boundaries. Commit message format: `task #N: <subject>` followed by body summarizing what changed and key Codex findings.

Do NOT batch tasks. One task → test → review → fix → commit → next task.

## Codex Review Workflow

Use the `/codex:review` plugin (not raw `codex exec`):

```
node "${CLAUDE_PLUGIN_ROOT}/scripts/codex-companion.mjs" review --background
```

Then `/codex:result <job-id>` for full output. Background mode is reliable; foreground often hangs on this host.

For challenge / design-question reviews use `adversarial-review` with explicit focus text:

```
node "${CLAUDE_PLUGIN_ROOT}/scripts/codex-companion.mjs" adversarial-review --background "<focus>"
```

Codex review uses git diff (working tree vs HEAD), so commit only **after** review passes. Iterate uncommitted with re-reviews until clean.

## Key Conventions

- **Error paths in eBPF return `TC_ACT_OK`.** Never drop packets. Bug in datapath = passthrough, not service outage.
- **Conntrack key**: `{pod_ip u32, pod_port u16, txid u16}`. Includes `txid` so concurrent A+AAAA queries from the same source port don't collide.
- **Egress TTL check**: `(now - timestamp_ns) > CONNTRACK_TTL_NS` (5s default) → delete + passthrough. Defends against stale entry colliding with unrelated direct VPC-DNS responses.
- **Egress does NOT honor `cfg->bypass`.** In-flight DNAT'd queries must still be SNAT'd back to CoreDNS so the pod never sees `src=host_resolver_ip`. Bypass affects ingress only.
- **TCX-only attach** (kernel 6.6+). No classic TC fallback in MVP. Programs auto-detach when controller process exits.
- **`hostResolverIP` is required** in config. No `/etc/resolv.conf` auto-detect (systemd-resolved nodes expose `127.0.0.53` loopback stub).
- **Wildcard-only patterns** in MVP (`*.suffix`). Loader rejects exact patterns and interior wildcards.
- **Rules are unordered.** Any matching suffix triggers redirect. All MVP rules share the `host-resolve` action.
- **`QDCOUNT != 1` → passthrough** with `parse_error` metric.
- **VPC CNI network policy coexistence is post-MVP** (see `docs/vpc-cni-coexistence.md`). MVP assumes our programs are sole TC filter on host-side veth.
- **Inclusive language**: use primary/replica, allowlist/denylist (per Amazon convention).

## Design Source of Truth

- `docs/design.md` — full design spec (datapath, controller, config, edge cases).
- `docs/tasks.md` — ordered implementation tasks with dependency graph.
- `docs/example-walkthrough.md` — end-to-end packet trace.
- `docs/vpc-cni-coexistence.md` — post-MVP coexistence design.

When design and code disagree, design wins until explicitly updated.
