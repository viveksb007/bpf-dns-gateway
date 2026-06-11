# Live Validation — S3 DNS Redirection

End-to-end proof that the gateway diverts matching S3 DNS queries to the node's
VPC resolver instead of CoreDNS, run on the `example-cluster` EKS cluster
(2 nodes, kernel 6.12).

This complements the unit/integration suites (`internal/**/*_test.go`,
`test/integration/`) and the per-task live evidence in `docs/audit-impl/`.
Those prove the datapath/controller in isolation; this proves the *whole
system* against a real workload on a real cluster.

## The challenge

The redirect is designed to be invisible: a pod sends to the CoreDNS ClusterIP,
ingress rewrites the destination to the VPC resolver, egress rewrites the source
back to CoreDNS. From inside the pod nothing looks different, so "it resolved"
proves nothing. Validation has to observe the **node-side path** and **datapath
state**, and isolate the gateway as the *cause* with an A/B.

## Setup

- **Gateway**: deployed as the DaemonSet (`deploy/daemonset.yaml`) using the
  image built from the repo `Dockerfile`, pushed to ECR
  (`144465910773.dkr.ecr.us-west-2.amazonaws.com/bpf-dns-gateway:dev`). 2/2 ready.
- **Workload**: 4-replica Deployment, each pod looping every 2s:
  ```
  getent hosts test-bucket.s3.us-west-2.amazonaws.com   # uses /etc/resolv.conf -> CoreDNS ClusterIP -> gateway
  ```
  `getent` (not `dig @server`) is required so the query goes through
  `/etc/resolv.conf` → the CoreDNS ClusterIP, which is what the gateway
  intercepts (it only matches dst == CoreDNS ClusterIP : 53). The name matches
  rule `*.s3.us-west-2.amazonaws.com`.
- **CoreDNS** (temporarily, restored after): Corefile patched to add the `log`
  plugin and freeze S3 answers with cache MINTTL:
  ```
  log
  cache 600 {
    success 9984 600 600
    denial  9984 600 600
  }
  ```
  Plain `cache 30` was not enough — CoreDNS honors S3's ~5s record TTL and would
  rotate IPs on both paths, collapsing the IP-set signal. MINTTL=600 floors the
  TTL so CoreDNS serves one frozen S3 set for 10 min.

> **Blast radius note:** patching the cluster CoreDNS Corefile affects all
> cluster DNS. The ConfigMap was snapshotted before and restored after
> (`cache 30`, no `log`/MINTTL). It was a dev cluster and explicitly requested.

## Validation signals (4 independent, must all agree)

### 1. CoreDNS query log — decisive
With the `log` plugin, CoreDNS records every query it actually receives. If the
gateway works, CoreDNS sees **zero** of the real FQDN
`test-bucket.s3.us-west-2.amazonaws.com.` from the workload pods (they are
DNAT'd to the VPC resolver before reaching CoreDNS).

Care needed separating two query classes in the log:
- **search-suffix expansions** (`...svc.cluster.local`, `...us-west-2.compute.internal`,
  …) — emitted by the stub resolver's ndots search. These do **not** match the
  rule (they end in `cluster.local` etc.) and correctly pass through to CoreDNS
  (all NXDOMAIN). Thousands of these are expected and irrelevant.
- the **bare FQDN** ending in `amazonaws.com.` — the real query. This is the one
  that must not reach CoreDNS while the gateway is active.

### 2. IP-set divergence (frozen CoreDNS vs rotating VPC resolver)
With CoreDNS frozen (MINTTL=600), a direct query to a CoreDNS pod IP returns a
stable set **C**. The workload (via the gateway → VPC resolver, honoring S3's
real ~5s TTL) sees fresh, rotating sets **G**. `G` containing IPs outside `C`
⇒ the answers did not come from frozen CoreDNS.

Note: counting **per-source query deltas** in the CoreDNS log (signal 1) turned
out cleaner and less ambiguous than diffing the rotating IP sets, because S3
returns large multi-record answers that shift slightly even under MINTTL. The
IP-set view is corroborating, not primary.

### 3. Gateway eBPF datapath metrics
Scrape `/metrics` on each node (`:9153`, hostNetwork):
- `bpf_dns_gateway_suffix_match_total` climbs ~1 per matched S3 query → DNAT'd.
- `bpf_dns_gateway_egress_snat_total` climbs ~1 per response → SNAT'd back.
- `bpf_dns_gateway_suffix_no_match_total` only climbs for non-matching names.

### 4. Bypass A/B (causation)
Force the health-driven bypass by pointing `hostResolverIP` at a blackhole
(`192.0.2.1`, TEST-NET-1) via the ConfigMap + DS rollout. After the failure
threshold the gateway sets `bypass_active=1` and ingress stops DNAT'ing. Same
workload, opposite outcome: S3 queries now reach CoreDNS. Restoring the real
resolver swings it back. This rules out ambient routing — the gateway's state
is the only variable.

## Results

### Steady-state, per-source real-FQDN deltas to CoreDNS (Δ over 60s)

| Source | gateway ACTIVE | under BYPASS |
|--------|----------------|--------------|
| workload pod 192.168.8.169  (node1) | **0** | **30** |
| workload pod 192.168.14.8   (node1) | **0** | **30** |
| workload pod 192.168.49.12  (node2) | **0** | **30** |
| workload pod 192.168.61.215 (node2) | **0** | **30** |
| dnstool 192.168.4.119 (queries CoreDNS pods directly, never via gateway) | 0 | 0 |

~30 queries/60s/pod under bypass = one per ~2s loop, exactly the workload rate.
Active = 0 across all pods.

### Gateway metrics
- Active: `suffix_match_total` and `egress_snat_total` climbing 1:1 with the
  workload (observed live: 2568 → 2872 → 2920 over the run); `bypass_active 0`.
- Bypass: `bypass_active 1`, `health_check_failures` climbing (8), fresh-pod
  `suffix_match_total 0`.

### IP sets
Gateway-active workload received fresh 8-IP S3 sets rotating every ~5s (VPC
resolver). Direct CoreDNS query returned a near-frozen set (MINTTL). Workload
IPs included addresses outside the frozen CoreDNS set.

### The swing = proof

| State | workload S3 FQDN → CoreDNS | gateway suffix_match |
|-------|---------------------------|----------------------|
| **gateway active** | 0 / 60s (all pods) | climbing |
| **bypass** | ~30 / 60s (all pods) | flat at 0 |

Traffic deterministically follows the gateway's state.

## Notable finding — startup-window leak (expected, quantified)

Before steady-state, each pod sent a burst of real-FQDN queries to CoreDNS
(cumulative 250 / 250 / 24 across pods) and then **delta 0** for the rest of its
life. These are queries issued in the window **before the gateway attached TCX
to that pod's freshly-created veth**. This is the documented boot-gap behavior
(decision `docs/audit/001-daemonset-deployment.md`, design §7.2): a DaemonSet
pod starts after kubelet/CNI, so pods created in that window use CoreDNS until
startup reconciliation attaches to their veths. It is correct and safe
(pre-attach → CoreDNS, never an outage), not a steady-state leak. The systemd/AMI
deployment (which starts before kubelet) shrinks this window further.

## How to reproduce

1. Build + push the image; `kubectl apply -f deploy/configmap.yaml -f deploy/daemonset.yaml` (edit image ref).
2. Snapshot CoreDNS ConfigMap; add `log` + `cache 600 { success 9984 600 600 }`; `rollout restart deploy/coredns`.
3. Deploy the 4-replica `getent` workload against `test-bucket.s3.us-west-2.amazonaws.com`.
4. Confirm CoreDNS sees **0** real-FQDN queries from workload pods over a 60s
   window (filter the log for `"A IN test-bucket.s3.us-west-2.amazonaws.com. "`,
   exclude search-suffix expansions); confirm gateway `suffix_match_total` climbing.
5. Patch `hostResolverIP` → `192.0.2.1`, rollout; confirm `bypass_active 1` and
   that CoreDNS now receives ~1 real-FQDN query/pod/loop.
6. Restore CoreDNS ConfigMap and gateway config; delete workload + DS.

## Cleanup performed

Gateway DS + ConfigMap, workload Deployment, and helper pods deleted. CoreDNS
ConfigMap restored to the original (`cache 30`, no `log`/MINTTL) and rolled out;
CoreDNS healthy. The ECR repo remains in the account.
