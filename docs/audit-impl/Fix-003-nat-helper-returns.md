# Fix 003 — Checked NAT helper returns with revert (eBPF datapath)

**Status:** complete
**Commit:** (this commit)
**Files:** `bpf/dns_gateway.{c,h}`, `internal/ebpf/maps.go`,
`internal/ebpf/dnsgateway_x86_bpfel.{go,o}` (regenerated),
`internal/metrics/collector.go`, `internal/metrics/collector_test.go`,
`test/integration/nat_metrics_test.go`, `README.md`, `docs/design.md` (§9.1)

## What

Closes the design.md §9.1 known correctness gap: the DNAT/SNAT rewrite
sequences ignored the return values of `bpf_skb_store_bytes`,
`bpf_l3_csum_replace`, and `bpf_l4_csum_replace`. A mid-sequence failure
would leave a packet half-rewritten (rewritten address + stale checksum
→ dropped downstream instead of falling back to CoreDNS) with conntrack
state diverged from packet state.

Changes:

- New `nat_rewrite_addr()` helper: performs address store + L3 csum +
  L4 csum with every return checked. On a mid-sequence failure it
  reverts the already-applied steps so the packet leaves either fully
  rewritten or byte-identical to arrival — never half-rewritten.
  Returns 0 / -1 (failed, cleanly reverted) / -2 (revert also failed).
- Ingress `do_dnat`: on NAT failure, deletes the just-inserted conntrack
  entry (state matches packet; query proceeds to CoreDNS as if never
  matched) and passes through.
- Egress SNAT: on NAT failure passes through with the conntrack entry
  retained (pod's resolver discards the src-mismatched response and
  retries; entry ages out via TTL/LRU). Conntrack delete +
  `METRIC_EGRESS_SNAT` now only fire on success.
- Two new counters: `METRIC_NAT_ERROR` (`nat_errors_total`) and
  `METRIC_NAT_REVERT_FAIL` (`nat_revert_failures_total`, "should stay
  0, alarm-worthy"), wired through `MetricID`, the Prometheus collector,
  README metric table, and design.md §9.1.

## How tested

Datapath change → live EKS verification per CLAUDE.md, adapted to the
currently available cluster `cl-load-test` (us-west-2, account
144465910773), node `ip-192-168-41-215`, **kernel 6.18.33**, amd64.
Privileged hostNetwork/hostPID pod (amazonlinux:2023, `/sys/fs/bpf`
bind-mounted), cross-compiled test binaries via `CGO_ENABLED=0 go test -c`,
`kubectl cp` + exec.

- **Repro note:** a helper failure cannot be forced from userspace (these
  helpers fail only on pathological offsets), so there is no live repro of
  the failure branch. The compile-time repro is the pre-fix source itself
  (returns discarded, README §"How it stays safe" documented the gap). The
  live testing therefore proves (a) the checked path is verifier-safe and
  (b) introduces no behavior change / false positives.
- **Verifier:** kernel 6.18 accepted both programs (every test below does a
  full load) — significant because MAX_LABELS=20 previously exhausted the
  1M-instruction budget on 6.18; the added branches did not tip it over.
- **`internal/ebpf` suite on-node:** 11/11 PASS (attach, populate, SetBypass,
  suffix rules, metrics, unpin).
- **Full integration suite on-node:** 22/22 PASS — all pre-existing
  DNAT/SNAT/bypass/conntrack/edge-case tests unchanged, plus new
  `TestNATRewrite_NoErrorsOnRoundTrip`: 50 DNAT+SNAT round trips through
  `BPF_PROG_TEST_RUN`; asserts `nat_errors_total` and
  `nat_revert_failures_total` deltas are exactly 0 while
  `suffix_match_total` and `egress_snat_total` advance by exactly 50
  (guards against the checked path silently short-circuiting).
- Local: `make generate` (clang 11) clean with `-Wall -Werror`;
  `go build ./...`, `go vet ./...`, `go test -race ./...` all pass;
  collector unit test asserts the two new Prometheus series export.
- Test pod deleted after the run.

## Review

Codex review tooling unavailable in this environment; self-reviewed per
repo checklist. Notable checks: error paths still return `TC_ACT_OK`
(never drop); egress reads `ct_val->coredns_ip` before the skb writes
(map value pointers are not invalidated by skb helpers, but the value is
passed by copy anyway); `BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | 4`
flags preserved verbatim from the original sequence.

## Decisions

- On egress NAT failure the conntrack entry is **kept** (not deleted):
  the response never reached the pod usably, so a client retry with the
  same txid/port can still be SNAT'd; TTL/LRU bounds the entry lifetime.
  Recorded here rather than docs/audit/ — no API/config impact.
- `METRIC_NAT_REVERT_FAIL` exists (rather than folding into
  `METRIC_NAT_ERROR`) because the two conditions have different severity:
  reverted = clean fallback to CoreDNS; revert-failed = possibly
  inconsistent packet on the wire, worth an alarm.
