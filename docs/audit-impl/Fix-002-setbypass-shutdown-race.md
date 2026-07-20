# Fix 002 — Shutdown SetBypass race (health checker vs teardown)

**Status:** complete
**Commit:** (this commit)
**Files:** `internal/health/checker.go`, `internal/health/shutdown_race_test.go`,
`internal/ebpf/loader.go`, `internal/ebpf/maps.go`,
`cmd/bpf-dns-gateway/main.go`, `docs/design.md` (§7.3)

## What

Two related races around the `config_map[0].bypass` flag at shutdown:

1. **Ordering race.** `run()` set the teardown `bypass=1` immediately after
   canceling the lifecycle ctx, but a health probe already in flight inside
   `Checker.Run` could complete afterwards; if the checker was in
   bypass-active state and the probe succeeded, its recovery path called
   `SetBypass(false)` — re-enabling ingress DNAT mid-teardown.
2. **Lost-update race.** `Loader.SetBypass` is a Lookup→Update
   read-modify-write with no serialization; concurrent calls from the
   checker goroutine and the shutdown path could interleave and lose the
   shutdown's write.

Fix (defense in depth):

- `Checker.probeOnce` returns without mutating any state once
  `ctx.Err() != nil` — after shutdown begins, ownership of the bypass flag
  transfers to the shutdown path. (Also avoids counting ctx-canceled
  probes as resolver failures.)
- `Checker.Done()` (closed when `Run` exits) lets `run()` wait for the
  checker — in-flight probe included — before setting the teardown bypass.
  Shutdown step order in `main.go` is now: wait checker → bypass=1 →
  wait controller detach → stop metrics → unpin/close.
- `Loader` gained `configMu`, serializing `PopulateConfig` and `SetBypass`
  writers of `config_map[0]`.
- `docs/design.md` §7.3 updated (design is source of truth): checker stop
  is now step 1, before the teardown bypass.

## How tested

Controller-Go logic; unit-testable without the cluster (the loader mutex
path is additionally exercised by the existing root-gated
`TestSetBypass` integration coverage, run on EKS in Fix-003's live pass).

- **Repro (pre-fix):** `TestShutdownRace_InFlightProbeClobbersShutdownBypass`
  drives a real `Checker` into bypass-active state, blocks a probe
  in flight, then performs main's old shutdown ordering (cancel ctx →
  `SetBypass(true)`), then releases the probe as a success. Pre-fix
  result: `FAIL ... final SetBypass call was false (calls=[true true false])`
  — the in-flight probe cleared the shutdown bypass.
- **Post-fix:** same test PASSES (kept as the regression test; models the
  worst-case ordering so the `probeOnce` ctx guard is what's proven).
  New `TestChecker_DoneClosedAfterRunExits` covers the `Done()` contract.
- Full unit suite `go test -race ./...`: all PASS (ebpf map tests SKIP
  locally — require root; covered live on EKS).
- `go build ./...`, `go vet ./...`, `gofmt -l` clean on touched packages.

## Review

Codex review tooling unavailable in this environment; self-reviewed per
repo checklist. Notable check: `probeOnce`'s ctx guard placed *after*
`c.query` returns, so a probe canceled mid-flight neither mutates bypass
nor increments `consecutiveFailures`/`probeFailures` spuriously at
shutdown.

## Decisions

- Kept the checker's 5s `Done()` wait bounded (mirrors the existing 10s
  controller-detach bound) so a hung DNS probe cannot stall shutdown; the
  probe timeout (default 2s) is well inside it. No `docs/audit/` doc —
  behavior change is shutdown-internal, no API/config impact.
