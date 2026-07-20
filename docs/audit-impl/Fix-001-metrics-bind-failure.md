# Fix 001 — Metrics server: fail startup on bind error

**Status:** complete
**Commit:** (this commit)
**Files:** `cmd/bpf-dns-gateway/main.go`, `cmd/bpf-dns-gateway/main_test.go`

> Naming note: all `docs/tasks.md` phases are complete; post-MVP bug fixes
> use `Fix-NNN-<slug>.md` instead of `Phase-N-Task-M-*`.

## What

`startMetricsServer` ran `ListenAndServe` inside a goroutine. If
`metricsAddr` was busy or invalid, the bind error was only logged from that
goroutine; `run()` received a `*http.Server` and continued, leaving the
process healthy-looking but with no `/metrics` or `/healthz` endpoint
forever (silent observability outage).

Fix: bind synchronously with `net.Listen` and return the error so `run()`
aborts startup (`start metrics server: bind metrics listener on ...`).
Only post-bind `Serve` errors remain log-only (runtime, not startup,
failures). `srv.Addr` now carries the actual bound address, which also
makes port-0 test listeners addressable.

## How tested

Pure controller-Go logic — no datapath change, unit-testable without the
cluster.

- **Repro (pre-fix):** a temporary test occupied a `127.0.0.1:0` port and
  called `startMetricsServer` with that address: no error surfaced to the
  caller and `/healthz` never became reachable (probe hung against the
  non-accepting listener until the 600s go-test timeout — mirroring how the
  production process would run blind). Output: `FAIL ... 600.104s`.
- **Post-fix regression tests** (`go test -race ./cmd/bpf-dns-gateway/`, PASS):
  - `TestStartMetricsServer_BusyPortReturnsError` — busy port → synchronous
    `bind metrics listener` error.
  - `TestStartMetricsServer_ServesHealthzAndMetrics` — success path serves
    200 on `/healthz` and `/metrics`.
- `go build ./...`, `go vet ./cmd/...`, `gofmt -l cmd/` all clean.

## Review

Codex review tooling (`codex:codex-rescue`) is not available in this
environment; self-reviewed against the repo review checklist (error paths,
test asserts behavior not just exercise, no API break — `startMetricsServer`
is package-private, config schema unchanged).

## Decisions

- none. Behavior change is fail-fast at startup only, matching the existing
  pattern of every other startup step in `run()` returning an error.
