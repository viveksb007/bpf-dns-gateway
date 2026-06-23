# Benchmark — S3 DNS IP Diversity + Latency (1000 pods, with vs without gateway)

Scale benchmark of the practical payoff of bypassing CoreDNS for S3 DNS. Run on
the `example-cluster` EKS cluster, scaled to 40 × m5.large for the duration.
Complements `docs/testing.md` (functional correctness); this measures **outcome
at scale**.

## Hypothesis

When many pods resolve the same S3 name:
- **Without the gateway**, all pods funnel through CoreDNS, whose shared 30s
  cache pins them to one ~8-IP answer set → low IP diversity, S3 load
  concentrated on a few frontends.
- **With the gateway**, each query is DNAT'd independently to the node VPC
  resolver, and S3 rotates ~8 IPs per answer → high IP diversity, load spread
  across many S3 frontends.

Also: does the eBPF DNAT/SNAT add DNS latency? (It also *removes* the CoreDNS hop.)

## Method

- **Cluster**: nodegroup `ng-825abf38` scaled 2 → 40 m5.large for the run, back
  to 2 after. ~1000 schedulable pods.
- **Workload**: a stdlib-only Go tool (`test/loadgen/`), 1000-replica Deployment.
  Each querier resolves `test-bucket.s3.us-west-2.amazonaws.com.` via the Go
  resolver (→ `/etc/resolv.conf` → CoreDNS ClusterIP → gateway), timestamps each
  lookup, and streams every returned IP + latency to an in-cluster aggregator
  (`/report` → unique-IP count + p50/p95/p99).
- **Two modes**: *steady* (each pod ~2 q/s for 60s) and *coordinated* (all pods
  fire at a shared wall-clock epoch — a thundering herd).
- **Gateway A/B**: "with" = real resolver (`169.254.169.253`); "without" =
  `hostResolverIP` → `192.0.2.1` blackhole + DS rollout → health checker sets
  `bypass_active=1`, ingress stops DNAT'ing, S3 falls back to CoreDNS (verified:
  `bypass_active=1` on all sampled nodes; CoreDNS `log` showed ~20k real S3 FQDN
  queries arriving during the "without" arms, ~0 during "with").
- **CoreDNS**: default `cache 30` kept (realistic production baseline); `log`
  plugin added for corroboration; ConfigMap snapshotted + restored.

## Results

| Arm | Unique S3 IPs | Samples | Errors | p50 | p95 | p99 | max |
|-----|--------------:|--------:|-------:|----:|----:|----:|----:|
| **with**-steady       | **3095** | 120000 | 0   | 0.74 ms | 2.55 ms | 5.66 ms | 19 ms |
| **without**-steady    | **163**  | 116339 | 393 | 1.10 ms | 2.18 ms | 4.62 ms | 4004 ms |
| **with**-coordinated  | **1083** | 1827   | 7   | 3.27 ms | 16.8 ms | 24.6 ms | 46 ms |
| **without**-coordinated | **31** | 1257   | 209 | 3.78 ms | 204 ms  | 4003 ms | 4018 ms |

### Diversity (the headline)
- **Steady: 3095 vs 163 unique IPs — ~19× more diversity with the gateway.**
- **Coordinated: 1083 vs 31 — ~35× more.**

Without the gateway, 1000 pods collapse onto the handful of IPs in CoreDNS's
shared cache entry. With the gateway, independent VPC-resolver queries surface
thousands of distinct S3 frontend IPs in 60s.

### Latency
- Steady p50: **0.74 ms with vs 1.10 ms without** — the gateway is *faster* at
  the median; the saved CoreDNS hop outweighs the in-kernel DNAT/SNAT cost.
- The large `without` tails (p99/max up to ~4 s, plus errors) come from CoreDNS
  cache-miss/forward bursts — especially under the coordinated thundering herd,
  where 1000 simultaneous uncached queries overwhelm CoreDNS (without-coordinated
  p95 ≈ 204 ms, 209 errors) while the gateway path stays clean (with-coordinated
  p95 ≈ 17 ms, 7 errors).

## Caveats / honesty notes

- **Coordinated arms are a near-simultaneous burst, not a perfect single shot.**
  Cross-pod epoch alignment over 1000 pods is lossy (busy-wait + the pod's brief
  keep-alive), so sample counts vary (1827 / 1257) and absolute numbers drifted
  between reads. The **steady arms are the rigorous measurement**; coordinated is
  directional, illustrating herd behavior. The diversity gap holds in both.
- Errors in the `without` arms are CoreDNS-side timeouts under load (the workload
  resolver had a 4s timeout → ~4004 ms max). They are a property of routing S3
  through CoreDNS at this scale, not of the gateway.
- Go resolver vs glibc `getent`: both reach CoreDNS for an external name; FQDN
  used a trailing dot to avoid ndots search expansion.
- Single S3 name, single region, one cluster, one run — directional, not a
  benchmark suite.

## Reproduce

`test/loadgen/` holds the tool, its Dockerfile, and the `aggregator.yaml` /
`querier.yaml` manifests. Build the static binary, push an image, deploy the
aggregator, then per arm: set the gateway state (real resolver vs `192.0.2.1`
blackhole + DS rollout), set the querier ConfigMap (`ARM`/`QMODE`/`DURATION`/
`START_EPOCH`), scale the querier Deployment to 1000, run, and read
`GET /report?arm=`. Scale the nodegroup up first; scale it back and restore
CoreDNS after.

## Cleanup performed

Loadgen Deployment/Service/ConfigMap, gateway DS + ConfigMap deleted. CoreDNS
restored to original (`cache 30`, no `log`). Nodegroup `ng-825abf38` scaled back
to 2/2/2. ECR repo retained.
