# Phase 3 · Task 16 — Integration test: bypass mode + health checker

**Status:** complete
**Commit:** (this commit)
**Files:** `test/integration/bypass_test.go`, `test/integration/testdns_test.go`, `internal/health/checker.go` (added `ProbePort`)

## What
Integration tests that exercise bypass + the real health checker against the real eBPF loader / config_map (the path #13 and #14 deferred to here):
- `TestBypassStopsIngressDNAT` — bypass=1 → matching query not DNAT'd, no conntrack entry.
- `TestEgressSNATsInFlightUnderBypass` — the key invariant: a query DNAT'd before bypass flips is still SNAT'd on egress (egress ignores `cfg->bypass`) so the pod never sees `src=host_resolver_ip`.
- `TestHealthCheckerActivatesAndClearsBypass` — real `health.Checker` probing an unreachable resolver (192.0.2.1 / TEST-NET-1) flips bypass ON in the real config_map after the failure threshold.
- `TestHealthCheckerRecoversBypass` — full fail→recover on ONE long-lived checker against a togglable local DNS responder (`toggleDNS`): starts dropping queries → bypass ON; flipped to answering → bypass CLEARS. Drives the real config_map both ways.
- `TestConntrackFreshWithinTTL` — a response within `CONNTRACK_TTL_NS` is SNAT'd and its conntrack entry deleted.
- `TestConntrackStaleBeyondTTL` — backdates the pinned conntrack entry's `TimestampNs` to 0, then sends the response: egress hits the `now - timestamp_ns > CONNTRACK_TTL_NS` branch → passthrough unmodified (src stays host_resolver_ip) + stale entry deleted.

Adds `readBypass`/`waitBypass` helpers (read bypass straight from the pinned `config_map`) and a `toggleDNS` test responder. Added `ProbePort` to `health.Config` (default 53) so a test can point the checker at a local responder on a random port.

## How tested
- Build: `go build ./...` + `go vet ./test/integration/...` clean.
- Live (EKS), node `ip-192-168-3-205` (kernel 6.12), privileged hostNetwork pod, `/sys/fs/bpf` bind-mounted — cross-compiled test binary, `-test.run "Bypass|Egress|Health|Conntrack"`. All PASS:
  - ingress bypass: matching query unmodified, no conntrack.
  - egress-under-bypass: response src rewritten to CoreDNS despite bypass=1.
  - health activate: 3 consecutive `i/o timeout` probes to 192.0.2.1:53 → `bypass ENABLED` → real config_map bypass=1.
  - health recover: single checker against `toggleDNS` → `bypass ENABLED` then `bypass CLEARED` once the responder starts answering.
  - conntrack fresh-within-TTL: SNAT'd + entry deleted.
  - conntrack stale-beyond-TTL: backdated entry → passthrough unmodified + stale entry deleted (the TTL-expiry branch).
- Full pre-existing integration suite (`TestPassthroughBypass`, `TestSNATBypassesUnknownTxid`) + all other package tests still PASS.

## Review
Reviewed with the Codex plugin (`/codex:review`). Codex back online for this task.
- P2: original `TestHealthCheckerSharesConfigMap` only ever probed the unreachable resolver and cancelled once bypass became true — the recovery path was never exercised. Fixed: replaced with `TestHealthCheckerRecoversBypass` using a single long-lived checker + togglable responder (added `health.Config.ProbePort` to point it at a local server). The two-instance approach I first tried was itself wrong — recovery-clear only fires on the instance that set bypass (per-instance `bypassActive`), so a fresh checker never clears; one checker is both correct and matches production.
- P2: original `TestConntrackFreshWithinTTL` never reached the TTL-expiry branch. Fixed: added `TestConntrackStaleBeyondTTL` that backdates the pinned conntrack `TimestampNs` to 0 and asserts passthrough + deletion.
- P3 (round 2): new `ProbePort` field accepted out-of-range values (`-1`, `70000`) → every probe fails before DNS and could wrongly enable bypass. Fixed: `New` now rejects ports outside 1..65535; added `TestNew_RejectsInvalidProbePort` unit test.
- Round 3: clean.
- Final: clean.

## Decisions
- none. (`ProbePort` is a test-affordance with a 53 default; not a behavior change.)
