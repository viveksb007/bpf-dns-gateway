# Phase 4 · Task 20 — README (+ CLAUDE.md)

**Status:** complete
**Commit:** (this commit)
**Files:** `README.md` (new), `CLAUDE.md` (header + structure updated for the DaemonSet path).

## What
`README.md`: overview + why, ASCII architecture diagram (ingress DNAT + conntrack → VPC DNS → egress SNAT, with the failure-passthrough and TTL notes), requirements (kernel 6.6+, VPC CNI, bpffs), build (`make` + docker), config reference (with the required-`hostResolverIP` and wildcard-only/case-sensitive caveats), both deploy paths (systemd recommended, DaemonSet optional with the decision-doc link), full Prometheus metric table, safety summary, MVP limitations, dev pointer to CLAUDE.md + docs/.

## How tested
Docs task — no code/live test. Verified:
- All 9 intra-repo links resolve to existing files (`docs/*`, `deploy/*`, `CLAUDE.md`).
- All 14 `bpf_dns_gateway_*` metric names in the README table match the names registered in `internal/metrics/collector.go` (scripted grep — every one `ok`).
- Config example matches `deploy/config.yaml` schema; kernel/arch/CNI claims match `docs/design.md` §11 + decision 001.

## Review
Reviewed with the Codex plugin (`/codex:review`). 4 rounds:
- P2: README "errors → passthrough" guarantee was too absolute — design §9.1 documents the unchecked NAT/checksum-helper-return gap. Qualified the claim + linked §9.1.
- P3: diagram + safety bullet described the stale-conntrack TTL branch as "drop"; the implementation deletes the entry and passes through (`TC_ACT_OK`, asserted by `TestConntrackStaleBeyondTTL`). Reworded to passthrough.
- P2: CLAUDE.md still said "Runs as systemd service, not DaemonSet" and listed only old deploy artifacts, contradicting the new DaemonSet path. Updated CLAUDE.md header + structure.
- Round 4: clean.
- Final: clean.

## Decisions
- none.
