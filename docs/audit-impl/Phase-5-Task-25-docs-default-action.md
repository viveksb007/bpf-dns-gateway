# Phase 5 · Task 25 — Docs: README, deploy examples, ndots caveat

**Status:** complete
**Commit:** (this commit)
**Files:** `README.md`, `CLAUDE.md`, `deploy/config.yaml`, `deploy/configmap.yaml`

## What

User-facing docs for the defaultAction feature (issue #1):

- **README** — Configure section documents `defaultAction`, the per-query
  action model (most-specific-match-wins), the no-op validation rule, and
  a complete "non-cluster mode" example with the ndots:5 search-domain
  caveat; metrics table gains `redirected_total` / `cluster_resolved_total`
  and updates the `suffix_match/no_match` meanings; stale "rules are
  unordered; any match redirects" line removed.
- **CLAUDE.md** — key-conventions bullet replaced: rules carry actions,
  precedence is most-specific-match (longest-first label walk), validation
  invariant noted.
- **deploy/config.yaml** — `defaultAction` documented with a commented-out
  non-cluster mode block (cluster.local, in-addr.arpa, ip6.arpa, stub-zone
  hint) and the ndots caveat.
- **deploy/configmap.yaml** — `defaultAction` added with a pointer to the
  non-cluster example.

## How tested

Docs-only; no datapath change. `TestDeployExampleConfigValid` re-parses
`deploy/config.yaml` through the real config loader — PASS (the edited
example remains valid, including the new `defaultAction` key). Full
`go test ./...` and `make fmt-check` pass.

## Review

Codex review tooling unavailable in this environment; self-reviewed:
cross-checked every doc claim against the implemented behavior (metric
names against `collector.go`, validation message against `config.go`,
precedence against `dns_gateway.c`).

## Decisions

- none.
