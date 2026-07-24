# Phase 5 · Task 22 — Config: `defaultAction` + `cluster-resolve` action

**Status:** complete
**Commit:** (this commit)
**Files:** `internal/config/config.go`, `internal/config/default_action_test.go`

## What

Config schema for issue #1 (design.md §8/§8.1): top-level
`defaultAction: cluster-resolve|host-resolve` (omitted → `cluster-resolve`,
so existing configs parse to identical semantics), `cluster-resolve`
accepted as a rule action alongside `host-resolve`. New validation:
unknown defaultAction/action values rejected; at least one rule must have
an action different from `defaultAction` (all-restating configs are
no-ops; the `host-resolve`-default variant of that mistake would send
cluster service discovery to the VPC resolver, so its error message hints
at the missing `*.cluster.local` / `*.in-addr.arpa` rules).

## How tested

Pure config-parsing logic — unit-testable without the cluster.

- 7 new tests in `default_action_test.go`: omitted default → cluster-resolve;
  host-resolve mode parse; mixed actions; invalid defaultAction rejected;
  invalid rule action rejected; host-resolve default without cluster-resolve
  rule rejected (with cluster-breakage hint asserted); all-rules-restate-
  default rejected for cluster-resolve mode too.
- All 5 pre-existing config tests pass unchanged, including
  `TestDeployExampleConfigValid` (deploy/config.yaml example still valid →
  backward compatible).
- `make fmt-check`, `go build ./...`, full `go test ./...` clean.

## Review

Codex review tooling unavailable in this environment; self-reviewed per
repo checklist. Backward-compat check: `DefaultAction` empty-string default
applied in `applyDefaults` before `Validate`, so `Load`/`Parse` callers
never see an empty action.

## Decisions

- none beyond design.md §8.1 (validation rule specified there).
