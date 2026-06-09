# Phase 3 · Task 13 — Health checker

**Status:** complete
**Commit:** (this commit)
**Files:** `internal/health/checker.go`, `internal/health/checker_test.go`, `internal/health/testserver_test.go`, `go.mod`, `go.sum`

## What
Periodic VPC DNS resolver probe that toggles the eBPF bypass flag. Sends an A query (`amazon.com.` by default) over UDP via `miekg/dns`. After `FailureThreshold` consecutive failures it sets `bypass=1`; a single success after being failed clears it. Any DNS response (incl. NXDOMAIN/SERVFAIL) counts as healthy — we only care that the resolver answered. Exposes `ProbeFailures()` and `BypassActive()` for the metrics collector. `Run(ctx)` probes once immediately then on an interval ticker; returns on ctx cancel.

## How tested
- Build: `make build` clean (`GOPROXY=off` — local proxy is down; deps `miekg/dns@v1.1.72` already in module cache).
- Unit (`go test ./internal/health/...`, 5 tests, all PASS):
  - `EnablesBypassAfterThreshold` — no SetBypass before threshold; bypass=true on Nth consecutive failure; idempotent while failed; ProbeFailures counts every failure.
  - `ClearsBypassOnRecovery` — bypass=false on first success after failing.
  - `NoBypassWhenHealthy` — never toggles while healthy.
  - `SingleFailureThenRecoverNoFlap` — sub-threshold failure + success resets counter, no toggle.
  - `UDPQuery_AgainstLocalServer` — real `miekg/dns` UDP server on 127.0.0.1: `udpQuery` returns nil against it, errors against a dead `127.0.0.1:1`.
- Live (EKS): **not required.** Pure control-flow + local UDP DNS. Probe behavior is fully exercised by the in-process miekg/dns server; the BypassSetter is an interface and is integration-tested against the real loader in Task #16 (bypass + health integration test).

## Review
Codex backend was returning server errors / stream disconnects during this task, so review was done with `caveman-review` (per user direction to fall back until Codex recovers).

- 🟡 race: `ProbeFailures()`/`BypassActive()` read `probeFailures`/`bypassActive` from the (future) metrics-collector goroutine while `probeOnce` writes them from `Run`. Fixed: `probeFailures` → `atomic.Uint64`, `bypassActive` → `atomic.Bool`. Verified with `go test -race ./internal/health/...` (clean).
- 🔵 nit: redundant double timeout (`dns.Client{Timeout}` + `context.WithTimeout`). Fixed: dropped the client field, rely on `ExchangeContext` ctx deadline.
- ❓ consecutiveFailures unbounded during long outage — int, ~years to overflow; intentional, no change.

Final: clean after fixes. Re-review with Codex when backend recovers (optional; findings were low-severity).

## Decisions
- none. (Any-RCODE-is-healthy and probe-once-on-start are design.md §7.5-consistent; not new decisions.)
