# Phase 5 · Task 24 — Integration test: host-resolve default mode

**Status:** complete
**Commit:** (this commit)
**Files:** `test/integration/default_action_test.go`

## What

Live behavioral coverage for `defaultAction: host-resolve` ("non-cluster"
mode) per design.md §6.2/§8 and tasks.md #24:

- `TestDefaultHostResolve_NonMatchRedirected` — query matching no rule is
  DNAT'd to the VPC resolver, conntrack created, `redirected_total` +1.
- `TestDefaultHostResolve_ClusterSuffixPassthrough` — `*.cluster.local`
  query passes through byte-identical, no conntrack,
  `cluster_resolved_total` +1.
- `TestDefaultHostResolve_ReverseLookupPassthrough` — `*.in-addr.arpa`
  (pod/service PTR) passes through untouched.
- `TestDefaultHostResolve_MostSpecificRuleWins` — `*.amazonaws.com
  host-resolve` + `*.s3.amazonaws.com cluster-resolve`: S3 name stays on
  CoreDNS (longest-suffix-first precedence), non-S3 amazonaws.com name is
  DNAT'd.
- `TestDefaultHostResolve_BypassPassthrough` — bypass=1 stops
  default-action redirects too.
- `TestDefaultHostResolve_ResponseSNAT` — egress SNAT of a response to a
  default-action-redirected query (egress is conntrack-driven and
  action-agnostic).

## How tested

Live EKS per CLAUDE.md, cluster `cl-load-test`, node `ip-192-168-41-215`
(kernel 6.18.33), privileged pod, cross-compiled test binary,
`BPF_PROG_TEST_RUN` harness (same as the pre-existing suite).

- All 6 new tests PASS on-node; full suite 28/28 PASS (pre-existing 22
  unchanged — allowlist mode behavior identical).
- Test pod deleted after the run.

## Review

Codex review tooling unavailable in this environment; self-reviewed per
repo checklist: tests assert behavior (byte-equality, conntrack state,
metric deltas), not just exercise code — each would fail against a no-op
or inverted datapath.

## Decisions

- none.
