# Research Paper Data-Collection Plan

## Objective

Collect reproducible correctness, performance, resource, answer-distribution,
compatibility, and failure data for the mechanisms defined in
[`research-paper-recommendation.md`](research-paper-recommendation.md):

- clean ClusterDNS/CoreDNS;
- NodeLocal DNSCache;
- bpf-dns-gateway;
- direct-VPC and gateway-bypass diagnostic controls.

Do not start confirmatory collection until the harness, metadata capture, run
validation, and analysis pipeline pass the pilot acceptance gates below.

## Definition of complete

Complete collection only when all of the following exist:

- immutable environment and software version manifests;
- raw artifacts for every retained and excluded run;
- at least 10 valid independent blocks for every headline result;
- correctness results for every mechanism/query/protocol cell;
- latency, reliability, capacity, resources, cache, path, and state metrics for
  every primary performance run;
- DNS-answer and actual connection-frequency datasets;
- fault timelines and recovery measurements;
- analysis scripts that regenerate every paper figure and table;
- an exclusion log with predefined reasons and no silently deleted runs;
- a cluster restoration and cost record.

## Safety and cluster policy

- Use a dedicated, non-production EKS cluster and AWS account.
- Do not patch production CoreDNS, node images, conntrack settings, or VPC
  Resolver paths.
- Snapshot every modified ConfigMap, DaemonSet, Deployment, sysctl, and nodegroup
  setting before the first run.
- Store restoration commands and original objects in the experiment artifacts.
- Restore CoreDNS, nodegroups, sysctls, DaemonSets, and test zones after each
  campaign.
- Disable VPC CNI NetworkPolicy for the primary gateway comparison. The current
  gateway documents coexistence as post-MVP in
  [`vpc-cni-coexistence.md`](vpc-cni-coexistence.md).
- Record cost-generating resources and define an automatic cleanup deadline.

## Required repository additions

Implement these artifacts before collecting paper data. Keep the existing
`test/loadgen/` unchanged so [`benchmark-diversity.md`](benchmark-diversity.md)
remains reproducible.

```text
experiments/paper/
  core.yaml                 # cluster, arms, SLO, run budget, restoration hashes
test/paper/
  loadgen/                  # raw DNS and application clients
  manifests/                # workload, collector, Prometheus, node collector
  node-image/               # pinned AMI recipe: binary, config, systemd unit
  queries/                  # versioned query distributions
  zones/                    # controlled-zone records and TTL schedule
hack/paper/
  build-node-image.sh       # produce one immutable AMI for every primary arm
  bootstrap.sh              # create namespace and monitoring components
  configure-arm.sh          # install and verify exactly one mechanism
  run.sh                    # execute one manifest-defined run
  collect.sh                # collect metrics, logs, configs, and kernel state
  validate-run.sh           # apply mechanical acceptance gates
  cleanup.sh                # restore the cluster after a run/campaign
analysis/paper/
  requirements.lock         # pinned analysis environment
  ingest.py                 # raw artifacts → columnar tables
  validate.py               # dataset-level reconciliation
  analyze.py                # statistics and derived metrics
  figures.py                # regenerate publication figures
  tables.py                 # regenerate publication tables
  tests/                    # synthetic fixtures and analysis unit tests
schemas/paper/
  experiment.schema.json
  result.schema.json
```

Treat the command interface below as the required implementation contract; the
scripts do not exist yet:

```bash
hack/paper/build-node-image.sh --experiment experiments/paper/core.yaml
hack/paper/bootstrap.sh --experiment experiments/paper/core.yaml
hack/paper/configure-arm.sh --arm cluster-dns --output "$RUN_DIR"
hack/paper/run.sh --manifest "$RUN_DIR/run.yaml"
hack/paper/collect.sh --run-dir "$RUN_DIR"
hack/paper/validate-run.sh "$RUN_DIR"
hack/paper/cleanup.sh --experiment experiments/paper/core.yaml
```

Fail fast when a script detects an unexpected Corefile, active competing
mechanism, missing metric target, partial Pod placement, or unready workload.

## Harness requirements

### DNS microbenchmark client

Implement or pin a client that supports:

- explicit server, QNAME, QTYPE, QCLASS, UDP/TCP, and IPv4/IPv6 transport;
- open-loop offered QPS independent of response completion;
- configurable concurrency and source Pod count;
- deterministic query lists and random seeds;
- one-hot, Zipfian, uniform, and unique-name distributions;
- monotonic per-query timestamps;
- response RCODE, TC bit, answer addresses, TTLs, and response size;
- timeout and late-response recording;
- HDRHistogram or equivalent lossless mergeable histograms;
- local buffering with batch upload after the timed interval;
- attempted, sent, completed, late, lost, and malformed counters.

Do not perform synchronous HTTP telemetry in the query loop. Verify that the
load generator can exceed the highest system-under-test capacity by at least
25% while staying below 70% CPU on generator Pods/nodes.

Pin the Kubernetes `perf-tests/dns` tooling or `dnsperf` image by commit and
image digest for an independent capacity cross-check.

### Application client

Implement a separate normal-resolver workload that records:

- DNS lookup duration;
- connection establishment and TLS duration;
- time to first byte and total request latency;
- HTTP result and retry count;
- all returned DNS addresses;
- selected remote address;
- node, Pod, Availability Zone, mechanism, and run ID.

Use a fixed small S3 object and disable application-level response caching.
Control connection reuse explicitly: run one campaign with a new connection per
request and one with production-like keep-alive.

### Controlled authoritative zone

Create a test zone with deterministic records for:

- TTL 0, 5, 30, and 300 seconds;
- rotating A and AAAA sets;
- fixed A and AAAA sets;
- NODATA and NXDOMAIN;
- large DNSSEC/EDNS0 responses;
- a response that triggers UDP truncation and TCP retry.

Before the pilot, choose and pin one implementation that supports every required
TTL and response behavior: either a delegated private namespace served by a
versioned authoritative server in the VPC, or a Route 53 hosted zone after
verifying that it supports the required semantics. Record delegation, Resolver
rules, server image/configuration, health checks, and zone hashes. Do not change
the authority implementation between arms.

Generate unique labels from `run_id`, client ID, and sequence number. Retain the
zone definition and authoritative query logs. Use real S3/ECR names in a
separate external-validity campaign.

## Artifact layout

Do not commit large raw results to Git. Store them in versioned object storage
with retention enabled; commit schemas, scripts, checksums, and a small sample
fixture.

```text
results/paper/raw/<run-id>/
  run.yaml
  checksums.sha256
  environment/
    cluster.yaml
    nodes.tsv
    versions.json
    coredns-corefile.txt
    coredns-objects.yaml
    mechanism-objects.yaml
    workload-objects.yaml
    sysctls.tsv
  client/
    counters.json
    latency.hdr
    queries.parquet
    answers.parquet
    connections.parquet
  prometheus/
    range-queries.json
    targets.json
  kernel/
    conntrack-before.json
    conntrack-during.json
    conntrack-after.json
    bpf-programs.json
    bpf-maps.json
    softirq.tsv
  mechanism/
    gateway-metrics.prom
    coredns-metrics.prom
    nodelocal/
      <node-name>.prom
  logs/
  validation.json
```

Use run IDs with sortable, explicit dimensions:

```text
YYYYMMDDTHHMMSSZ-b<block>-<arm>-<workload>-p<pods>-q<offered-qps>-r<repeat>
```

## Run manifest

Record at least:

```yaml
schemaVersion: 1
runId: 20260811T010000Z-b01-bpf-gateway-external-miss-p1000-q10000-r01
campaign: capacity
block: 1
repeat: 1
randomSeed: 48151623
arm: bpf-gateway
cacheMode: production-default
cluster:
  name: paper-cluster
  region: us-west-2
  kubernetesVersion: "<captured>"
  nodeImage: "<captured>"
  kernel: "<captured>"
  nodeInstanceType: m5.large
  nodeCount: 40
  cni: "<captured>"
  kubeProxyMode: iptables
coredns:
  version: "<captured>"
  replicas: 2
  corefileSha256: "<captured>"
gateway:
  gitCommit: "<captured>"
  imageDigest: "<captured>"
  deployment: systemd
nodelocal:
  version: null
workload:
  name: external-miss
  pods: 1000
  duration: 5m
  warmup: 1m
  cooldown: 1m
  offeredQps: 10000
  qtype: A
  transport: udp4
  distribution: unique
  timeout: 30s
  queryFileSha256: "<captured>"
measurement:
  prometheusStep: 5s
  packetCapture: sampled
  bpfRuntimeAccounting: true
```

Generate the manifest before the run. Never infer missing dimensions later from
file names or dashboards.

## Environment capture

Capture a complete snapshot before every campaign and a compact verification
inside every run directory. Keep campaign provenance separate from immutable
per-run evidence.

Initial commands:

```bash
export EXPERIMENT_ID="paper-$(date -u +%Y%m%dT%H%M%SZ)"
export ARTIFACT_ROOT="results/paper/raw"
export CAMPAIGN_ROOT="results/paper/campaigns/$EXPERIMENT_ID"
export TEST_NAMESPACE="dns-paper"
mkdir -p "$CAMPAIGN_ROOT/environment"

kubectl version -o yaml > "$CAMPAIGN_ROOT/environment/kubectl-version.yaml"
kubectl get nodes -o wide > "$CAMPAIGN_ROOT/environment/nodes.txt"
kubectl get nodes -o yaml > "$CAMPAIGN_ROOT/environment/nodes.yaml"
kubectl -n kube-system get deploy,ds,svc,cm -o yaml \
  > "$CAMPAIGN_ROOT/environment/kube-system.yaml"
kubectl -n kube-system get cm coredns -o yaml \
  > "$CAMPAIGN_ROOT/environment/coredns-original.yaml"
```

At run creation, set `RUN_DIR="$ARTIFACT_ROOT/$RUN_ID"`, create
`$RUN_DIR/environment`, and copy the campaign manifest plus a fresh targeted
configuration/hash verification into it. Do not overwrite campaign or prior-run
artifacts.

Also capture:

- EKS version and platform version;
- EC2 AMI ID, instance type, CPU model, NUMA layout, and Availability Zone;
- kernel command line and relevant sysctls;
- VPC CNI, kube-proxy, CoreDNS, NodeLocal, gateway, container runtime, and load
  generator image digests;
- service and Pod CIDRs, IP-family policy, MTU, and DNS search configuration;
- kube-proxy version and mode, held fixed for all primary arms;
- per-node `ip route`, `ip rule`, ENI/secondary-IP inventory, VPC CNI prefix
  delegation, and warm-IP/prefix settings;
- CoreDNS replicas, resources, placement, PodDisruptionBudget, and Corefile;
- node and cluster autoscaler state;
- AWS Resolver-related quotas visible to the account;
- NTP/clock synchronization status.

Hash every captured configuration and include the hashes in each run manifest.

## Instrumentation

### Client measurements

Write one record per query containing:

```text
run_id, block, arm, node, pod, client_id, sequence, monotonic_start_ns,
duration_ns, qname_id, qtype, transport_family, protocol, response_code,
truncated, answer_count, answer_addresses, answer_ttls, response_bytes,
timed_out, late, malformed
```

Keep QNAMEs in a separate dictionary table when unique names make the event
file too large.

### CoreDNS and NodeLocal metrics

Collect raw counters/histograms and resource metrics, including:

- `coredns_dns_requests_total`;
- `coredns_dns_request_duration_seconds`;
- `coredns_dns_responses_total`;
- `coredns_dns_request_size_bytes` and `coredns_dns_response_size_bytes`;
- `coredns_cache_requests_total` and `coredns_cache_hits_total`;
- `coredns_cache_entries` and `coredns_cache_evictions_total`;
- process/container CPU, working set, throttling, restarts, and OOM events.

Label and store central CoreDNS separately from each NodeLocal instance. Derive
cache misses as requests minus hits where required by the installed CoreDNS
version.

### Gateway metrics

Collect every exported metric, including:

- `bpf_dns_gateway_ingress_total_packets`;
- `bpf_dns_gateway_dns_queries_total`;
- `bpf_dns_gateway_suffix_match_total`;
- `bpf_dns_gateway_suffix_no_match_total`;
- `bpf_dns_gateway_redirected_total`;
- `bpf_dns_gateway_cluster_resolved_total`;
- `bpf_dns_gateway_bypass_packets_total`;
- `bpf_dns_gateway_parse_errors_total`;
- `bpf_dns_gateway_egress_total_packets`;
- `bpf_dns_gateway_egress_snat_total`;
- `bpf_dns_gateway_egress_conntrack_miss_total`;
- `bpf_dns_gateway_nat_errors_total`;
- `bpf_dns_gateway_nat_revert_failures_total`;
- `bpf_dns_gateway_attached_veths`;
- `bpf_dns_gateway_bypass_active`;
- `bpf_dns_gateway_suffix_rules_loaded`;
- `bpf_dns_gateway_health_check_failures`;
- `bpf_dns_gateway_scrape_errors_total`.

Read BPF program runtime and map metadata on every node. On the dedicated test
cluster, enable runtime accounting only for runs that need it and restore the
original value afterward:

```bash
ORIGINAL_BPF_STATS="$(sysctl -n kernel.bpf_stats_enabled)"
sudo sysctl -w kernel.bpf_stats_enabled=1
bpftool -j prog show > bpf-programs.json
bpftool -j map show > bpf-maps.json
sudo sysctl -w kernel.bpf_stats_enabled="$ORIGINAL_BPF_STATS"
```

Run these commands through the node collector; do not assume the local shell is
the node host.

### Kernel and network metrics

Collect before, during, and after each run:

- `nf_conntrack_count` and `nf_conntrack_max`;
- `conntrack -S`, including insert failures and drops;
- UDP DNS flow counts and drain time;
- CPU modes, softirq time, context switches, packet drops, and interface bytes;
- TCX attachment inventory;
- optional sampled packet captures at Pod veth, CoreDNS, and node egress.

Use captures only for path verification and representative traces; do not enable
full packet capture in headline performance runs.

### Prometheus range export

Export raw range-query responses rather than screenshots. Use a 5-second step
for resources and a 1-second step for fault timelines. Include a pre-run and
post-run window to establish idle baseline and recovery.

Validate metric labels before the pilot because cAdvisor and managed Prometheus
label sets vary by cluster.

## Mechanism arms

### `cluster-dns`

- Remove the gateway program and NodeLocal DNSCache completely.
- Verify Pods use the CoreDNS ClusterIP.
- Verify no gateway TCX links remain on sampled and randomly selected nodes.
- Restore the canonical Corefile and fixed CoreDNS replica/resources.

### `node-local`

- Remove the gateway completely.
- Install a NodeLocal DNSCache manifest pinned to the cluster Kubernetes version
  and record its digest.
- Record kube-proxy mode and whether Pods use the service IP or a dedicated
  local address.
- Verify NOTRACK rules, local listener readiness, per-node placement, central
  upstream path, and metrics on every node.

Do not download an unpinned `master` manifest during a run. Check the selected
manifest into the experiment assets or store it by immutable commit.

### `bpf-gateway`

- Remove NodeLocal DNSCache completely.
- Build one immutable custom AMI from `test/paper/node-image/`. Bake the pinned
  gateway binary, `/etc/bpf-dns-gateway/config.yaml`, and
  `deploy/bpf-dns-gateway.service` into it with the service disabled by default.
- Use that same AMI for every primary arm. In this arm only, enable/start the
  service on every node before workload Pods start. In other arms, stop/disable
  it and prove no TCX links remain.
- Record the AMI ID, image recipe hash, gateway commit, binary hash, config hash,
  and systemd unit hash.
- Verify `attached_veths` matches eligible veth inventory, bypass is zero, and
  `suffix_rules_loaded` matches the manifest.
- Verify redirected and cluster-resolved canary names before load starts.

Run a separate operational campaign with the DaemonSet deployment to quantify
its startup attachment window.

### Diagnostic arms

- `direct-vpc`: use only controlled external names. Set `dnsPolicy: None` and
  `dnsConfig.nameservers` to the VPC+2 IPv4 address or `169.254.169.253`; record
  the selected address. The link-local address is served per instance. This Pod
  intentionally loses ClusterDNS service discovery, so never use this arm for
  Kubernetes names.
- `bpf-bypass`: exercise the documented health-driven path. Blackhole or block
  the configured VPC Resolver on the dedicated test nodes, wait for
  `failureThreshold` consecutive probe failures, and require
  `bpf_dns_gateway_bypass_active == 1`. Do not write the BPF config map directly.
  Restore reachability, require one successful recovery probe, and retain egress
  long enough for in-flight gateway transactions to drain; see
  [`design.md`](design.md) §7.5.

## Query suites

Create immutable query files with checksums:

| ID | Contents | Cache purpose |
|----|----------|---------------|
| `external-hot` | One eligible controlled-zone name | Warm positive cache |
| `external-zipf100` | 100 eligible names, Zipfian frequency | Mixed realistic locality |
| `external-zipf1000` | 1,000 eligible names | Cache-capacity sensitivity |
| `external-unique` | Unique eligible name per request | Controlled cache misses |
| `internal-service` | Existing Kubernetes Services | Cluster correctness/load |
| `internal-pod` | Existing Pod records; capture/assert the CoreDNS `pods` plugin mode and expected NXDOMAIN behavior | Kubernetes plugin behavior |
| `nxdomain-hot` | One nonexistent name | Negative cache |
| `nxdomain-unique` | Unique nonexistent names | Negative misses |
| `reverse` | IPv4 and IPv6 PTR names | Reverse-zone behavior |
| `search-list` | Relative external names | `ndots` amplification |
| `rotating` | Controlled rotating sets plus S3/ECR | Diversity |
| `large-response` | EDNS0/DNSSEC and truncated UDP | Protocol fallback |

Use a trailing dot for absolute-name tests. Keep relative-name tests in a
separate workload so search expansion is intentional.

## Collection campaigns

### Campaign 0 — harness calibration

- Run against a fixed local DNS responder with known latency and loss.
- Verify offered QPS, latency histogram accuracy, timeout accounting, and merged
  histograms.
- Cross-check a subset against `dnsperf`.
- Confirm generator CPU remains below 70% and the network reporter is inactive
  during the timed interval.
- Inject known RCODEs, delay, loss, malformed responses, truncation, and TCP
  fallback.
- Verify all raw records reproduce aggregate counters exactly.

Exit gate: measured QPS within 1% of offered QPS below saturation, no silent
sample loss, and p50/p99 within an agreed tolerance of the injected latency.

### Campaign 1 — correctness and compatibility

Run each primary mechanism at low QPS for:

- every query suite;
- A and AAAA;
- UDP over IPv4 and IPv6 where supported;
- TCP over IPv4 and IPv6;
- EDNS0, DNSSEC, truncation, long/mixed-case names, fragments, and multi-question
  packets;
- normal, host-network, and `dnsPolicy: None` clients.

Compare RCODE, answer semantics, TTL bounds, source transparency, and fallback
path. DNS answers need not be byte-identical when upstream rotation is expected.

Exit gate: no unexpected resolution failures or semantic changes; all expected
fallbacks are proven by path metrics or packet traces.

### Campaign 2 — saturation discovery

For `external-hot`, `external-unique`, `internal-service`, and `nxdomain-unique`:

1. Hold Pod/node layout fixed.
2. Start below expected capacity.
3. Double offered QPS until loss exceeds 1% or p99 exceeds the declared SLO.
4. Repeat the ramp three times per mechanism.
5. Select confirmatory points near 25%, 50%, 75%, 100%, and 125% of the observed
   SLO-compliant capacity.

Do not reuse one mechanism’s absolute QPS points blindly when capacities differ.
Include common absolute loads for direct comparison and normalized loads for
behavior near each mechanism’s knee.

### Campaign 3 — confirmatory performance

Run the three mechanisms at the selected load points for:

- hot positive cache;
- Zipfian mixed cache;
- unique cache misses;
- internal Service names;
- unique NXDOMAIN.

Use:

- 1-minute warmup;
- 5-minute measured interval;
- 1-minute cooldown;
- 10 randomized blocks for primary cells;
- 5 blocks for secondary diagnostic cache-disabled cells.

Run production-default cache configurations first. Run CoreDNS and NodeLocal
cache-disabled variants as a separate decomposition campaign. Do not call the
VPC Resolver path “cache disabled.”

### Campaign 4 — Pod, node, and density scaling

Run two independent sweeps:

1. Pods `{10, 100, 500, 1000}` at fixed per-Pod QPS.
2. Per-Pod QPS from low load through saturation at a fixed Pod count.

At selected aggregate loads, compare:

- more nodes with fewer Pods per node;
- fewer nodes with more Pods per node.

Collect veth attachment count/lag, per-node cache/resource skew, CoreDNS endpoint
placement, state occupancy, and query-source distribution. Use at least five
blocks per cell and 10 for cells used in headline scaling figures.

### Campaign 5 — redirect-ratio offload

Generate deterministic mixtures containing 0%, 25%, 50%, 75%, and 100%
gateway-eligible names while holding total QPS fixed. Run separate curves for
`external-hot` and `external-unique`; do not mix cache localities within one
curve.

Measure:

- CoreDNS QPS and CPU;
- VPC-bound/upstream QPS where observable;
- gateway kernel CPU and map activity;
- client latency and errors.

Fit and report the CoreDNS offload curve. Check whether gateway cost is linear
with inspected or redirected packets.

### Campaign 6 — diversity and application impact

For the controlled rotating zone and real S3/ECR names:

- run steady Poisson-like arrivals and coordinated bursts;
- cover at least two TTL classes and multiple names;
- record complete answer ordering and TTLs;
- run new-connection and keep-alive application modes;
- record the selected remote IP for every connection;
- use 10 blocks per headline cell.

Calculate unique count, entropy, normalized entropy, Gini coefficient, top-k
concentration, max/mean ratio, and cross-node Jaccard overlap. Bootstrap
confidence intervals by run/block, not by individual address.

### Campaign 7 — state pressure

Drive concurrent UDP A and AAAA queries from many Pods while increasing offered
QPS. Continue until the first of:

- client error threshold;
- Linux conntrack pressure;
- BPF map pressure or miss increase;
- mechanism saturation;
- safe cluster resource limit.

Record occupancy and drain curves for Linux conntrack and the gateway BPF map.
Repeat with NodeLocal to verify its NOTRACK behavior. Do not deliberately exhaust
shared production limits.

### Campaign 8 — faults and lifecycle

Inject one fault at a time during a stable steady load:

| Mechanism | Faults |
|-----------|--------|
| ClusterDNS | delete/restart one replica, remove an endpoint, exhaust fixed CPU, upstream delay/loss |
| NodeLocal | restart/OOM local Pod, remove local rules/listener in a controlled test, central CoreDNS failure, upstream delay/loss |
| Gateway | VPC Resolver blackhole, controller graceful stop, controller kill, node reboot, config rollout, rapid veth churn |

For each event, record a 1-second timeline covering at least two minutes before
and five minutes after the fault. Measure lost queries, tail latency, affected
Pods/nodes, detection, fallback, and full recovery. Run at least five blocks per
fault and 10 for the primary availability claim.

### Campaign 9 — IPv4/IPv6 and protocol boundary

Run the full transport/QTYPE matrix at low and medium load:

- UDP4/A, UDP4/AAAA;
- UDP6/A, UDP6/AAAA;
- TCP4/A, TCP4/AAAA;
- TCP6/A, TCP6/AAAA.

Add a normal dual-stack application workload. Separate DNS transport family
from returned address family in every table and figure. For the current gateway,
report IPv6/TCP as fallback compatibility rather than accelerated paths.

### Campaign 10 — kernel and portability

Repeat a small confirmatory subset on supported kernels already relevant to the
repository, including 6.6, 6.12, and 6.18 when node images are available.

Treat eBPF load success as a gate before traffic tests. Record the known
kernel-6.18 verifier sensitivity: the repository reduced `MAX_LABELS` to 10
after a 20-label build exceeded the one-million-instruction verifier limit. Fail
the arm explicitly if a tested build does not load; do not silently omit that
kernel.

Collect verifier load success, BPF program metadata, latency, CPU/query, and
correctness. Keep this campaign out of the primary mechanism ranking unless
identical hardware and cluster conditions are available.

## Per-run protocol

Execute every measured run in this order:

1. Generate `run.yaml`, random seed, query file, and run directory.
2. Configure exactly one mechanism.
3. Verify component versions, image digests, Corefile hash, resources, Pod
   placement, metrics targets, and mechanism isolation.
4. Run low-rate canaries for eligible external, nonmatching external, internal,
   NXDOMAIN, A, and AAAA names.
5. Establish the requested cache state. Restart only controllable caches; use
   unique names for VPC Resolver misses.
6. Capture pre-run client, resource, cache, kernel, BPF, and configuration state.
7. Run warmup without retaining it in the measured latency distribution.
8. Start the measured interval and mark start/end timestamps.
9. Stop offered load, flush client buffers, and capture the cooldown/recovery
   interval.
10. Collect post-run counters, Prometheus ranges, logs, kernel/BPF snapshots,
    events, and object manifests.
11. Reconcile attempted/sent/completed/lost client counts with mechanism and
    DNS-server counter deltas.
12. Run mechanical validation and write `validation.json`.
13. Mark the run retained or excluded; never delete it.
14. Cool down or restore the cluster before the next randomized arm.

## Mechanical run validation

Reject a run from confirmatory analysis when any predefined condition holds:

- wrong or multiple mechanisms active;
- unexpected Corefile/config/image hash;
- fewer than 99% of workload Pods ready at measured start;
- failed metrics scrape for more than 1% of the interval;
- generator CPU at or above 70% or generator packet loss;
- attempted/sent/completed/lost counters do not reconcile;
- sample timestamp outside the measured interval;
- clock step or node reboot not part of the experiment;
- autoscaler or unrelated workload changed node capacity;
- CoreDNS, NodeLocal, gateway, or workload OOM/restart outside a fault campaign;
- gateway NAT revert failures are nonzero;
- expected path counters do not prove the configured arm.

Do not reject a run merely because the system under test timed out, returned an
error, saturated, or used more resources. Those are outcomes.

## Randomization and repetitions

- Define one block as one execution of every compared mechanism for the same
  workload/load/environment cell.
- Use a balanced Latin-square or deterministic shuffled order within blocks.
- Persist the randomization seed before collection.
- Use different query seeds per block but the same seed across mechanisms within
  a block.
- Run at least 10 blocks for headline cells and five for secondary cells.
- Repeat a full block after any cluster repair, upgrade, or node replacement.
- Do not mix pre-change and post-change blocks without a version factor.

## Statistical analysis

Pre-register:

- primary outcomes and SLO;
- headline cells;
- exclusion rules;
- minimum effect sizes of interest;
- confidence interval and multiple-comparison method.

Calculate:

- per-run latency quantiles and timeout/error proportions;
- offered and attained QPS;
- SLO-compliant capacity;
- CPU time/query and cluster-total memory;
- cache hit ratio and upstream amplification;
- conntrack/BPF occupancy and drain time;
- entropy, normalized entropy, Gini, concentration, and Jaccard overlap;
- detection, fallback, and recovery durations.

Use block-paired effect estimates with bootstrap 95% confidence intervals. Use
a paired nonparametric test when a hypothesis test is needed. Treat run/block as
the independent unit; use hierarchical bootstrap when retaining Pod/node
structure. Do not claim significance from per-query pseudo-replication.

Report absolute values, paired differences, ratios, confidence intervals, and
raw run counts. Plot full latency distributions or complementary CDFs for tail
and fault results.

## Data reconciliation

Require these identities within documented tolerance:

```text
attempted = locally_rejected + sent
sent = completed + timed_out + outstanding_at_shutdown
completed = successful + DNS_error_response + malformed_response
CoreDNS request delta ≈ queries proven to take the CoreDNS path
gateway redirected delta ≈ IPv4 UDP queries whose resolved action is host-resolve while bypass=0
gateway suffix-match delta ≈ queries matching a configured suffix rule
gateway suffix-no-match delta ≈ queries using the configured default action
gateway egress SNAT delta ≈ successful redirected responses
cache requests = cache hits + derived cache misses
```

Explain expected differences caused by retries, search-list expansion, sampled
metrics, scrape boundaries, and TCP fallback.

## Required paper outputs

Generate these directly from checked-in analysis code:

| Output | Source campaigns |
|--------|------------------|
| Query-path architecture | design + environment manifests |
| Latency/QPS saturation curves | 2–3 |
| SLO-compliant capacity table | 2–3 |
| CPU/query and memory comparison | 3–5 |
| Cache and upstream amplification | 3 and cache decomposition |
| Pod/node scaling curves | 4 |
| Redirect-ratio offload curve | 5 |
| DNS-answer and connection concentration | 6 |
| Conntrack/BPF occupancy curves | 7 |
| Fault and recovery timelines | 8 |
| Transport/QTYPE compatibility table | 1 and 9 |
| Kernel portability table | 10 |
| Threats-to-validity table | all campaign metadata |

## Threats to validity to record

- VPC Resolver cache and implementation are not controllable.
- AWS service DNS answers and backend fleets change over time.
- One region, Availability Zone distribution, instance family, or CNI limits
  external validity.
- NodeLocal and CoreDNS behavior depends on exact Corefile and versions.
- BPF runtime accounting and packet capture can perturb performance.
- The gateway is IPv4/UDP-only and its VPC CNI NetworkPolicy coexistence is not
  implemented.
- A controlled rotating zone approximates but does not reproduce AWS service
  topology decisions.
- Application connection reuse can hide DNS differences.
- Managed service quotas or neighboring workloads can create unobserved noise.

Block runs in time, randomize mechanism order, collect environment covariates,
and repeat a small subset on another cluster/region to quantify these risks.

## Pilot acceptance gate

Before the first confirmatory block, demonstrate one end-to-end pilot that:

- configures and positively verifies all three primary arms;
- produces a complete artifact directory and checksums;
- sustains the requested open-loop QPS without generator saturation;
- records explicit A and AAAA over IPv4 separately;
- captures CoreDNS, NodeLocal, gateway, kernel, BPF, and resource metrics;
- reconciles all client and mechanism counters;
- calculates latency quantiles, error rates, cache ratio, CPU/query, and answer
  entropy;
- regenerates a sample figure and table from an empty analysis environment;
- restores the cluster using `cleanup.sh` and proves the original hashes match.

Review the pilot artifacts before purchasing the full run budget.

## Collection checklist

- [ ] Freeze research questions, hypotheses, primary outcomes, and SLO.
- [ ] Implement and test the schemas, harness, collectors, validators, and
      analysis environment.
- [ ] Create and validate the controlled authoritative zone.
- [ ] Provision the dedicated cluster and capture the original state.
- [ ] Pin every version, image digest, query file, and manifest.
- [ ] Complete harness calibration.
- [ ] Complete correctness and compatibility gates.
- [ ] Discover saturation points.
- [ ] Approve the pilot artifact and estimated run/cost budget.
- [ ] Run randomized confirmatory blocks.
- [ ] Run scale, offload, diversity, state, fault, protocol, and portability
      campaigns.
- [ ] Re-run failed mechanical validations without deleting excluded artifacts.
- [ ] Freeze the raw dataset and publish checksums.
- [ ] Regenerate all figures/tables from the frozen dataset.
- [ ] Restore the cluster and controlled zone; record cleanup evidence.
- [ ] Archive configuration, raw data, analysis code, exclusions, and limitations.
