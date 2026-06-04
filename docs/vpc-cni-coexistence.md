# VPC CNI Network Policy Coexistence (Post-MVP)

> **Status**: Out of scope for MVP. The MVP assumes our programs are the sole TC filter on the host-side veth (VPC CNI network policy disabled, or no other TC BPF programs attached). This document captures the design for coexistence so it can be picked up after MVP.

## Background

EKS VPC CNI attaches its own TC BPF programs to pod veths for network policy enforcement. Multiple TC BPF programs coexist on the same clsact qdisc using **priority-based ordering** (lower priority number = runs first).

## Ordering Requirement

| Direction | Our program runs... | Reason |
|-----------|-------------------|--------|
| **Ingress** (pod → host) | **AFTER** VPC CNI | VPC CNI policy must evaluate against the original dst (CoreDNS). If we DNAT first, VPC CNI sees dst=VPC_DNS and may drop the packet per network policy. |
| **Egress** (host → pod) | **BEFORE** VPC CNI | We SNAT src from VPC_DNS → CoreDNS. VPC CNI then sees a normal DNS response from CoreDNS and allows it. If VPC CNI runs first, it sees src=VPC_DNS, which may violate policy. |

## Implementation

VPC CNI uses a known TC filter priority. We configure our programs with:

- Ingress priority: VPC CNI priority + 1 (run after)
- Egress priority: VPC CNI priority − 1 (run before)

On TCX (kernel 6.6+), explicit `BPF_F_AFTER` / `BPF_F_BEFORE` positioning is available.

**Fallback**: If VPC CNI network policy is not enabled on the cluster, there is no conflict. Our programs run as the sole TC filter.

## Configuration

```yaml
# TC filter priority (relative to VPC CNI)
# VPC CNI's priority is auto-detected; these offsets position our programs.
tcPriorityOffset: 1
```

## Edge Case

| Case | Behavior |
|------|----------|
| VPC CNI network policy blocking | TC priority ordering ensures our DNAT/SNAT is invisible to VPC CNI policy evaluation |

## Implementation Notes for Future Work

- Auto-detect VPC CNI TC filter priority on startup (enumerate existing filters on each veth's clsact qdisc).
- Add `attach.go` priority management: position our ingress filter after VPC CNI's ingress, our egress filter before VPC CNI's egress.
- On TCX, prefer `BPF_F_AFTER` / `BPF_F_BEFORE` over numeric priority.
- Integration test: run with VPC CNI network policy enabled, verify DNAT/SNAT remain transparent to policy enforcement.
