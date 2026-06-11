# Phase 3 · Task 15 — Main entrypoint + lifecycle

**Status:** complete
**Commit:** (this commit)
**Files:** `cmd/bpf-dns-gateway/main.go`, `internal/netlinkmon/monitor.go` (shutdown-noise fix), `go.mod`, `go.sum`

## What
The controller entrypoint. Ordered startup (design.md §7.2): load+validate config → load eBPF + pin maps → populate config_map + suffix_rules → build attach manager / netlink monitor / controller / health checker → register Prometheus collector + start metrics HTTP server (`/metrics`, `/healthz`) → start monitor + controller + health goroutines → `sd_notify(READY=1)`.

Ordered shutdown on SIGTERM/SIGINT (design.md §7.3): `sd_notify(STOPPING=1)` → `SetBypass(true)` (ingress stops new DNAT, egress keeps draining) → wait for controller `Done()` (detach all veths, 10s cap) → stop metrics server → `loader.Close()` + `loader.Unpin()` → exit.

`--config` (default `/etc/bpf-dns-gateway/config.yaml`) and `--pin-dir` flags. JSON slog at the configured level. `sd_notify` is a dependency-free `unixgram` write to `$NOTIFY_SOCKET`; no-op when unset (non-systemd runs).

## How tested
- Build: `go build ./cmd/bpf-dns-gateway` clean; static `CGO_ENABLED=0` binary. `go vet ./...` clean; `go test ./...` all pass.
- Live (EKS), node `ip-192-168-3-205` (kernel 6.12), privileged hostNetwork pod, `/sys/fs/bpf` bind-mounted, real config (CoreDNS 10.100.0.10, hostResolver 169.254.169.253, 2 rules):
  - **Startup**: binary came up, logged `ready`, `sd_notify` no-op (not under systemd). All 5 maps pinned under `/sys/fs/bpf/dns-gateway/`.
  - **Auto-attach**: the node's existing pod veths (`eni3031980e328`, `eni0ca8ce2ba2c`) attached via the monitor's ListExisting replay → `bpf_dns_gateway_attached_veths 2`.
  - **Metrics/health endpoints**: `curl :9153/metrics` served all `bpf_dns_gateway_*`; `bypass_active 0`, `health_check_failures 0` (real VPC DNS probe at 169.254.169.253 healthy). `/healthz` → `ok`.
  - **Live veth lifecycle**: `ip link add` a veth pair → `attached_veths` 2→4; `ip link del` → 4→2. Controller attach/detach driven by real netlink events.
  - **Ordered shutdown**: SIGTERM → log shows `shutdown signal received` → `detaching from all interfaces` → `shutdown complete`; process exited; pin dir removed (`/sys/fs/bpf/dns-gateway/` gone). Confirms bypass→detach→unpin ordering.
  - **Re-run after the monitor fix**: 0 ERROR lines in the shutdown log.

## Review
Codex backend was failing (`Task submission failed ... Engine not found`, 404) across retries, so reviewed with `caveman-review` (per standing instruction to fall back when Codex is unavailable).
- 🔵 nit: `loader.Close()+Unpin()` duplicated across 4 startup early-return paths. Fixed: extracted a `cleanupLoader` closure (early-startup-only; the normal path still unpins in ordered shutdown after detach).
- 🟡 risk (reviewed, no change): double `stop()` if monitor errors before shutdown — idempotent, harmless. `SetBypass(true)` at shutdown is correct given egress ignores bypass and TCX detach follows. Health-checker ERROR branch is currently dead (Run only returns nil) but harmless.
- No bugs. Final: clean after the nit fix.
- Re-review with Codex when the backend recovers (optional; only a nit was found).

## Decisions
- During live testing the first run logged `ERROR netlink subscription error: resource temporarily unavailable` at shutdown — the netlink socket read was interrupted as the subscription was torn down by ctx-cancel. Benign (process exited cleanly) but logged at ERROR and would trip alerts. Fixed in `monitor.go`: the `ErrorCallback` returns early when `ctx.Err() != nil`, so shutdown-time socket interruptions are not logged or treated as fatal. Minor, no `docs/audit/NNN-*.md` raised.
