# Phase 5 · Task 23 — eBPF + loader: action resolution datapath

**Status:** complete
**Commit:** (this commit)
**Files:** `bpf/dns_gateway.{c,h}`, `internal/ebpf/maps.go`,
`internal/ebpf/maps_test.go`, `internal/ebpf/dnsgateway_x86_bpfel.{go,o}`
(regenerated), `internal/metrics/collector.go`,
`internal/metrics/collector_test.go`, `cmd/bpf-dns-gateway/main.go`,
`internal/config/config.go` (Patterns() removed),
`internal/config/config_test.go`, existing integration tests (call sites)

## What

Datapath for issue #1 (design.md §6.1/§6.2/§10.1):

- `gateway_config._pad` → `default_action` (size unchanged);
  `ACTION_CLUSTER_RESOLVE = 2`. A stale `0` (pinned map from an older
  binary) is treated as cluster-resolve by the ingress program —
  preserves the original allowlist behavior.
- Ingress: resolved action starts as `cfg.default_action` and is replaced
  by the first matching rule's action. `label_offsets[]` is ordered
  longest-suffix-first, so first match == most-specific match (precedence
  for free). `cluster-resolve` → passthrough + `METRIC_CLUSTER_RESOLVED`;
  `host-resolve` → DNAT. `METRIC_REDIRECTED` increments only after the
  rewrite fully succeeds, so it means "actually left for the VPC
  resolver". `suffix_match/no_match` keep meaning "a rule matched /
  didn't" (either action).
- Loader: typed `Action`; `Config.DefaultAction` (zero → cluster-resolve,
  invalid rejected); `PopulateSuffixRules([]SuffixRule)` reconciles
  add/delete **and updates changed actions in place**; duplicate patterns
  with conflicting actions rejected.
- `main.go` maps validated config strings to BPF actions
  (`toBPFAction`); obsolete `config.Patterns()` removed.
- Collector exports `redirected_total` / `cluster_resolved_total`;
  suffix match/no-match help strings updated.

## How tested

Datapath change → live EKS per CLAUDE.md, cluster `cl-load-test`, node
`ip-192-168-41-215` (kernel 6.18.33, amd64), privileged pod +
cross-compiled test binaries.

- **Verifier:** kernel 6.18 accepted both programs (the reworked decision
  flow adds branches to the verifier-budget-sensitive match loop; the
  6.18 1M-instruction limit was the constraint that forced MAX_LABELS=10).
- **`internal/ebpf` on-node:** 11/11 PASS, including the extended
  `TestPopulateSuffixRules_AddDelete` asserting the action
  update-in-place path via direct map lookup.
- **Full integration suite on-node:** 28/28 PASS — 22 pre-existing tests
  unchanged (allowlist behavior identical) + 6 new Task-24 tests.
- Local: `make generate` clean (`-Wall -Werror`), `make fmt-check`,
  `go vet ./...`, `go test -race ./...` all pass; collector unit test
  asserts the two new Prometheus series.

## Review

Codex review tooling unavailable in this environment; self-reviewed per
repo checklist. Notable checks: `METRIC_REDIRECTED` placed after NAT
success (conntrack/NAT failure paths fall back to CoreDNS and count
`nat_errors_total` instead); egress untouched (conntrack-driven,
action-agnostic); stale-0 default_action semantics documented in the
header and covered by the "existing tests unchanged" result, since
`loadGateway` in older tests writes configs without DefaultAction.

## Decisions

- `suffix_match_total` semantics widened from "matched → DNAT'd" to
  "matched (either action)" instead of adding a third counter. For all
  pre-Phase-5 configs the emitted values are identical (all rules were
  host-resolve), so no dashboard breakage; the new `redirected_total` is
  the precise "DNAT'd" signal. Recorded here; no config/API impact.
