# Phase 3 · Task 17 — Integration test: DNS edge cases

**Status:** complete
**Commit:** (this commit)
**Files:** `test/integration/edge_cases_test.go`, `test/integration/redirect_test.go` (extracted `openConntrack` helper)

## What
Edge-case datapath tests run through the real eBPF ingress/egress programs (`BPF_PROG_TEST_RUN`) on a real node. Each crafts a malformed/boundary packet and asserts passthrough + the right metric:
- `CompressionPointer` — QNAME starting with `0xC0` → passthrough + `parse_error++`.
- `QDCountZero` — QDCOUNT=0 → passthrough.
- `QDCountTwo` — QDCOUNT=2 with a matching first question → passthrough + `parse_error++` (ambiguous intent).
- `LabelLenTooLong` — label length byte `0x40` (64) → passthrough + `parse_error++`.
- `TCPOnPort53` — IPPROTO_TCP dst:53 → ignored (protocol != UDP), passthrough.
- `UDPChecksumZero` — matching query with UDP csum 0 → DNAT'd, csum stays 0 (`BPF_F_MARK_MANGLED_0`).
- `QNAMEOver128` — wire QNAME > `MAX_DNS_NAME_LEN` (128) → passthrough.
- `ManyShortLabels` — > `MAX_LABELS` (20) labels → passthrough.
- `UppercasePassthrough` — mixed-case QNAME does NOT match the lowercase rule → passthrough to CoreDNS (MVP no-BPF-lowercase limitation, design.md §9.1).
- `ConcurrentAandAAAA` — two queries, same source port, different txids (A + AAAA) → two distinct conntrack entries, both responses SNAT independently, both entries deleted. Proves the `txid` in the conntrack key prevents A/AAAA collision.

Adds `buildQueryProto` (UDP/TCP, optional zero csum), `dnsHeader`, `question`, `metricDelta`, `conntrackCount` helpers; extracted `openConntrack` shared with `conntrackExists`.

## How tested
- Build: `go build ./...` + `go vet ./test/integration/...` clean.
- Live (EKS), node `ip-192-168-3-205` (kernel 6.12), privileged hostNetwork pod, `/sys/fs/bpf` bind-mounted, cross-compiled test binary, `-test.run Edge`: all 10 PASS. Full integration suite (redirect + bypass + edge) PASS on the same node.

## Review
Reviewed with the Codex plugin (`/codex:review`). Round 1 clean — no findings (changes are test coverage + a shared `openConntrack` helper refactor).

## Decisions
- none. (Uppercase-passthrough asserts the already-recorded §9.1 limitation; not a new decision.)
