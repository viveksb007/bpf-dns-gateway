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

## Development Workflow

Work **phase by phase** through `docs/tasks.md`. This is the required loop —
follow it unless the user explicitly says otherwise.

**Per task** (one checklist item at a time):

1. **Code** the task.
2. **Test** it — build (`make build`/`make generate`), and validate behavior. For
   datapath/controller changes that means a live test on the cluster (see the
   EKS testing method below), not just a compile. Record the test method and
   evidence in `docs/audit-impl/Phase-<N>-Task-<M>-<slug>.md` (template +
   convention in `docs/audit-impl/README.md`).
3. **Review** the implementation *and* the test artifacts with Codex
   (`codex:codex-rescue`). Iterate until the review is clean. Codex has
   hallucinated file/line claims here — **verify every finding against the
   source** before acting on it.
   - If a **major decision** comes up (design trade-off, behavior change, an
     accepted limitation), **pull the user into the loop** before proceeding, and
     record the decision in a `docs/audit/NNN-*.md` doc.
4. **Commit** the task — in the same commit, check off its box in
   `docs/tasks.md` and include its `docs/audit-impl/Phase-N-Task-M-*.md` doc.
5. Move to the next task and repeat until the phase is complete.

**Per phase:** when every task in a phase is done, **stop and wait for the user**
to review all the commits and testing from that phase before starting the next
phase. Do not roll into the next phase automatically.

Keep commits scoped to one task. Don't push unless the user asks.

### EKS testing method

- Cluster: `viveksbh-Isengard@example-cluster.us-west-2.eksctl.io` (already in current kubectx).
- Node for live tests: `ip-192-168-3-205.us-west-2.compute.internal`, kernel 6.12.
- Privileged test pod pattern: `hostPID`, `hostNetwork`, `securityContext.privileged`, `/sys/fs/bpf` hostPath bind-mount, image `public.ecr.aws/amazonlinux/amazonlinux:2023` (`dnf install -y tar` before `kubectl cp`).
- Cross-compile test/smoke binaries `CGO_ENABLED=0 go test -c` → `kubectl cp` → exec in pod (root + bpffs needed for eBPF load, TCX attach, netlink).
- Pure-logic tasks (DNS wire encoding, config parsing) are unit-testable without the cluster — say so explicitly in the audit-impl doc.

### Codex review

Use the `codex:codex-rescue` agent for review. The companion script is also available directly:

```
node "${CLAUDE_PLUGIN_ROOT}/scripts/codex-companion.mjs" review --background
```

Then `/codex:result <job-id>` for full output. Background mode is more reliable; the reviewer occasionally returns "failed to output a response" — just re-run. `--wait` works when background flakes.

For challenge / design-question reviews use `adversarial-review` with explicit focus text:

```
node "${CLAUDE_PLUGIN_ROOT}/scripts/codex-companion.mjs" adversarial-review --background "<focus>"
```

Codex review uses git diff (working tree vs HEAD), so commit only **after** review passes. Iterate uncommitted with re-reviews until clean. **Verify every Codex finding against the actual source** before acting — it has cited wrong file/line claims on this repo.

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
