# Phase 3 · Task 14 — Prometheus metrics collector

**Status:** complete
**Commit:** (this commit)
**Files:** `internal/metrics/collector.go`, `internal/metrics/collector_test.go`, `go.mod`, `go.sum`

## What
`prometheus.Collector` that reads the per-CPU `metrics_map` (summed across CPUs by the loader's `ReadMetrics`) and the controller/health state on every scrape — pull model, no background goroutine, no staleness window.

Exposes (design.md §10.1):
- Datapath counters: `bpf_dns_gateway_{ingress_total_packets, dns_queries_total, suffix_match_total, suffix_no_match_total, bypass_packets_total, parse_errors_total, egress_snat_total, egress_conntrack_miss_total, egress_total_packets}`.
- Controller/health: `attached_veths` (gauge), `bypass_active` (gauge 0/1), `suffix_rules_loaded` (gauge), `health_check_failures_total` (counter).
- `scrape_errors_total` (counter) — incremented when a BPF map read fails during a scrape.

Decoupled via three small provider interfaces (`DatapathSource`, `AttachSource`, `HealthSource`) satisfied by `ebpf.Loader`, `ebpf.AttachManager`, `health.Checker`. `attach`/`health` may be nil (their metrics are then omitted) so the collector is usable before those subsystems exist.

## How tested
- Build: `make build` / `go build ./...` clean (`GOPROXY=off`, deps from module cache: `client_golang@v1.23.2` + transitive).
- Unit (`go test ./internal/metrics/...`, 5 tests, all PASS):
  - `AllMetricsPresent` — every datapath counter + every controller gauge emitted with expected values via a real `prometheus.Registry` + `Gather()`.
  - `BypassZeroWhenInactive` — gauge is 0 when health reports not-bypassed.
  - `ReadMetricsErrorIncrementsScrapeErrors` — datapath read error → counters omitted, `scrape_errors_total` = 1.
  - `CountErrorStillEmitsOthers` — `CountSuffixRules` error doesn't suppress datapath counters; `scrape_errors_total` = 1.
  - `NilAttachAndHealthOmitted` — nil sources → those metrics absent, datapath/suffix still present.
- Live (EKS): **done.** Throwaway `metrics-smoke` binary on node `ip-192-168-3-205` (kernel 6.12), privileged hostNetwork pod with `/sys/fs/bpf` bind-mounted: loaded the real eBPF programs, populated config + `*.s3.amazonaws.com`, drove one matching + one non-matching query through the ingress program via `BPF_PROG_TEST_RUN`, registered the real `Collector` against a `prometheus.Registry`, and gathered. Observed real per-CPU-summed values:
  - `ingress_total_packets 2`, `dns_queries_total 2`, `suffix_match_total 1`, `suffix_no_match_total 1`, `suffix_rules_loaded 1`, `scrape_errors_total 0`.
  - Confirms the real `metrics_map` → `ReadMetrics` → `Collector` → Prometheus exposition path end-to-end, not just fakes. Smoke binary was throwaway (removed after the run).

## Review
Reviewed with the Codex plugin (`/codex:review`). Codex backend recovered for this task. 3 rounds.
- P3 (round 1): `scrape_errors_total` counter was created without `Help`, while `Describe` advertised a separate desc that had Help — Describe/Collect descriptor mismatch + empty HELP in the exposition. Fixed: set `Help` on the `CounterOpts` and describe via `scrapeErrors.Desc()`; dropped the redundant `scrapeErrorsDesc` field. Verified against source (counter built its own family from its own desc).
- P2 (round 2): exported `health_check_failures_total`, but design.md §10.1 names it `health_check_failures` (no `_total`). Per CLAUDE.md "design wins until explicitly updated" — renamed to match. Verified against §10.1.
- Round 3: clean, no findings.
- Final: clean.

## Decisions
- `health_check_failures` kept without the `_total` suffix to match design.md §10.1, even though every other counter there (and Prometheus convention) uses `_total`. Treated as design-compliance, not a new decision; if we later normalize the name we update design + dashboards together. No `docs/audit/NNN-*.md` raised (minor naming, no behavior change).
