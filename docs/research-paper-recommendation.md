# Research Paper Recommendation

## Recommendation

Evaluate **when selective eBPF DNS bypass is preferable to shared cluster DNS
and per-node DNS caching**, rather than trying to prove that one mechanism is
universally best.

Use three primary mechanisms:

| ID | Mechanism | Query path | Added cache | Main optimization |
|----|-----------|------------|-------------|-------------------|
| `cluster-dns` | ClusterDNS/CoreDNS baseline | Pod → ClusterIP/kube-proxy → CoreDNS → upstream | Shared CoreDNS cache | Centralized service discovery and forwarding |
| `node-local` | NodeLocal DNSCache | Pod → node-local CoreDNS → CoreDNS/upstream on miss | Per-node cache | Local cache, `NOTRACK`, fewer cross-node hops |
| `bpf-gateway` | bpf-dns-gateway | Pod → TC eBPF → VPC Resolver for selected names | No gateway cache | Remove the CoreDNS hop for selected external names |

Add two diagnostic controls, but do not present them as primary mechanisms:

- `direct-vpc`: configure one external-name workload with `dnsPolicy: None` and
  the VPC Resolver as its nameserver. Use it to estimate the non-eBPF direct
  resolver path.
- `bpf-bypass`: leave the gateway attached with health bypass active. Use it to
  measure degradation behavior. Do not use it as the clean ClusterDNS baseline.

Follow the executable collection protocol in
[`research-paper-data-collection-plan.md`](research-paper-data-collection-plan.md).

## Proposed title

**Selective eBPF DNS Resolution in Kubernetes: Comparing Cluster-Wide,
Node-Local, and Direct VPC Resolver Paths**

## Central research question

> Under which workload, cache, scale, and failure conditions does selective
> in-kernel DNS redirection improve Kubernetes DNS latency, resource efficiency,
> and topology-aware answer distribution without compromising correctness or
> availability?

Separate the question into four claims:

1. **Datapath:** removing the CoreDNS hop reduces latency for eligible cache
   misses.
2. **Offload:** redirected traffic reduces CoreDNS QPS and resource demand.
3. **Answer distribution:** avoiding shared caches changes low-TTL rotating
   answer concentration and may improve actual backend load distribution.
4. **Safety:** unsupported traffic and failures fall back to CoreDNS with a
   bounded compatibility and recovery cost.

Do not combine these claims into one headline QPS result. Each has different
confounders and evidence requirements.

## Research questions

| ID | Question | Primary evidence |
|----|----------|------------------|
| RQ1 | How do client latency, loss, and SLO-compliant throughput differ? | Load/latency curves, timeout rates, saturation points |
| RQ2 | How do hot, mixed, cold, negative, and expired caches change the ranking? | Cache-hit ratios, client/upstream QPS, per-cache-state latency |
| RQ3 | How does each mechanism scale with Pods, nodes, Pod density, and per-Pod QPS? | Orthogonal Pod-count and offered-load sweeps |
| RQ4 | What is the total cluster CPU and memory cost? | CoreDNS, node-local, gateway, BPF, kernel, and map measurements |
| RQ5 | How do the mechanisms affect rotating-answer and actual connection distribution? | Entropy, Gini coefficient, concentration, remote connection IPs |
| RQ6 | What state pressure does each mechanism create? | Linux conntrack and gateway BPF map occupancy/errors |
| RQ7 | Which protocols, query classes, and IP families preserve correctness? | Compatibility matrix and response-semantic checks |
| RQ8 | How quickly and safely does each mechanism recover from failures? | Fault timelines, lost queries, detection/fallback/recovery time |

## Falsifiable hypotheses

- **H1 — eligible cache misses:** `bpf-gateway` has lower p95 and p99 client
  latency than `cluster-dns` for matching external UDP names carried over IPv4.
- **H2 — hot-cache boundary:** `node-local` has equal or lower latency and lower
  upstream QPS than `bpf-gateway` for workloads with a high local-cache hit
  ratio.
- **H3 — CoreDNS offload:** CoreDNS QPS and CPU fall approximately with the
  fraction of queries redirected by the gateway.
- **H4 — answer concentration:** for rotating low-TTL answers,
  `bpf-gateway` has lower concentration than `node-local`, which has lower
  concentration than the shared `cluster-dns` cache.
- **H5 — passthrough cost:** for cluster-internal and nonmatching names, gateway
  attachment adds a small, bounded kernel cost without changing DNS semantics.
- **H6 — resource trade-off:** NodeLocal DNSCache increases cluster-total
  userspace memory with node count, while the gateway shifts cost toward kernel
  CPU and BPF map state.
- **H7 — transport boundary:** gateway performance benefits apply to UDP DNS
  carried over IPv4, while IPv6 and TCP use the CoreDNS fallback path.
- **H8 — bounded failure:** loss and recovery after VPC Resolver failure are
  bounded by the configured health-check interval, timeout, and failure
  threshold.

Reject or narrow a hypothesis when its confidence interval includes no effect,
when a correctness gate fails, or when a result disappears after controlling
cache state. Negative and boundary results are part of the contribution.

## Independent variables

### Mechanism and configuration

- Mechanism: `cluster-dns`, `node-local`, `bpf-gateway`.
- CoreDNS and NodeLocal cache: production default and diagnostic cache-disabled
  variants.
- Gateway redirect fraction: 0%, 25%, 50%, 75%, and 100% of generated queries.
- CoreDNS replica count and CPU/memory allocation.
- Gateway deployment: a pinned custom node image with the systemd unit disabled
  by default for the primary result; enable it only in `bpf-gateway` arms.
  Use the DaemonSet for the startup and operational comparison.

Bake the gateway binary, unit, and config into the same immutable node image
used by every primary arm. Verify that the service is stopped and no TCX links
remain for `cluster-dns` and `node-local`; this preserves identical node
software and hardware while providing a reproducible systemd path.

The production-default arms answer “what should an operator deploy?” The
cache-disabled variants isolate path length from cache benefit. Keep those
results separate.

### Scale and load

Treat these as independent axes:

- total Pod count;
- total node count;
- Pods per node;
- per-Pod offered QPS;
- per-node offered QPS;
- aggregate cluster offered QPS;
- number of CoreDNS replicas;
- number and cardinality of queried names.

Do not use aggregate QPS as a substitute for Pod count. For example, 100 Pods ×
20 QPS and 1,000 Pods × 2 QPS exercise different veth, cache, source-address,
and scheduling behavior despite equal aggregate load.

### Query locality and cache state

- one hot name;
- Zipfian distribution over 100 and 1,000 names;
- uniformly distributed names;
- unique nonce names;
- cold cache;
- warm cache;
- query immediately before and after TTL expiry;
- positive and negative caching;
- TTL classes: 0, 5, 30, and 300 seconds where the authoritative test zone
  permits them.

The VPC Resolver contains a local/zonal cache that the experiment cannot flush.
Use unique names for controlled misses, stable names for warm-cache tests, and
record this limitation.

### Query semantics

Include:

- matching AWS external names;
- nonmatching external names;
- Kubernetes Service and Pod names;
- Route 53 private hosted-zone names;
- repeated and unique NXDOMAIN names;
- IPv4 and IPv6 reverse lookups;
- names expanded by the Pod `ndots` search list;
- low-TTL rotating answers;
- large EDNS0/DNSSEC responses;
- truncated UDP responses followed by TCP retry.

Run gateway fallback cases as correctness experiments: mixed-case names, more
than 10 labels, QNAMEs longer than 128 wire bytes, malformed or multi-question
packets, fragments, host-network Pods, and `dnsPolicy: None`.

### Record type versus transport family

Treat DNS record type and packet transport as separate dimensions:

| DNS transport | QTYPE | Current gateway behavior |
|---------------|-------|--------------------------|
| IPv4 UDP | A | Eligible for redirect |
| IPv4 UDP | AAAA | Eligible for redirect |
| IPv6 UDP | A | Falls through to CoreDNS |
| IPv6 UDP | AAAA | Falls through to CoreDNS |
| IPv4 or IPv6 TCP | A or AAAA | Falls through to CoreDNS |

“IPv4 only” describes the gateway packet parser, not the DNS QTYPE. Include
IPv4-only and dual-stack client tests. Include an IPv6-only environment only if
all three mechanisms can be configured fairly; otherwise report it as a known
compatibility boundary.

## Dependent variables

### Primary outcomes

- client p50, p90, p95, p99, and qualified p99.9 latency;
- timeout, loss, SERVFAIL, REFUSED, NXDOMAIN, and malformed-response rates;
- attained QPS and maximum QPS satisfying a declared latency/error SLO;
- application request latency, connection-establishment latency, and failure
  rate for a fixed S3 object workload;
- actual remote endpoint distribution for application connections;
- failure detection, fallback, and recovery time.

Report counts above 5 ms, 20 ms, 100 ms, 1 second, and 5 seconds. Keep failed
queries in the reliability analysis instead of dropping them from latency
results.

### Resource outcomes

Measure the entire subsystem:

- CoreDNS aggregate and per-replica CPU, working set, throttling, and restarts;
- NodeLocal aggregate, per-node, and maximum CPU/memory;
- gateway controller CPU and RSS;
- BPF program runtime and invocation count;
- node system and softirq CPU;
- BPF map memory and occupancy;
- completed queries per CPU-second, CPU time per query, and cluster-total MiB.

Container metrics alone undercount the gateway because its datapath executes in
kernel context.

### Cache and path outcomes

- CoreDNS and NodeLocal cache requests, hits, entries, and evictions;
- client QPS, CoreDNS QPS, and upstream QPS;
- backend-query amplification from `ndots` and search domains;
- UDP/TCP split and request/response bytes;
- gateway redirected, cluster-resolved, parse-error, NAT-error, and conntrack
  miss counters.

### State pressure

- Linux `nf_conntrack` count, maximum, insert failures, and drops;
- UDP DNS conntrack entries and drain time;
- gateway BPF conntrack-map occupancy and evictions, where observable;
- `bpf_dns_gateway_egress_conntrack_miss_total`;
- entry decay after offered load stops.

NodeLocal DNSCache explicitly installs `NOTRACK` rules for the local path. The
current gateway design does not establish that Linux conntrack is bypassed and
also maintains a 65,536-entry BPF transaction map. Measure both state systems;
do not assume a conntrack advantage.

### Answer and connection distribution

Collect per-answer and per-connection frequencies, then calculate:

- unique IP count;
- Shannon entropy;
- normalized entropy;
- Gini coefficient;
- top-1 and top-5 concentration;
- maximum-to-mean frequency ratio;
- Jaccard overlap across Pods and nodes;
- time to observe a changed answer set.

Separate:

1. every address returned in an answer;
2. the first/preferred address exposed to the application;
3. the remote address actually used for a connection.

Unique-IP count alone is not a load-balancing result. Normalize diversity by
measurement duration and effective TTL. Use both a controlled rotating-answer
zone and real S3/ECR names.

## Experimental structure

Use four layers:

1. **Correctness:** gate every query class at low load.
2. **DNS microbenchmark:** control QTYPE, transport, name distribution, cache
   state, concurrency, and offered QPS.
3. **Application benchmark:** measure S3 connection and request outcomes with a
   normal resolver stack.
4. **Fault and operations benchmark:** measure resolver, process, Pod, and node
   lifecycle events.

Run an initial load ramp to locate each mechanism’s saturation knee. Run the
confirmatory experiment below, at, and above that knee instead of choosing only
one low load.

## Fairness requirements

- Use a dedicated non-production cluster.
- Pin Kubernetes, EKS platform, kernel, VPC CNI, kube-proxy version and mode,
  CoreDNS, NodeLocal, gateway, load-generator, and node image versions.
- Keep node types, Availability Zone placement, CoreDNS replicas, Corefiles,
  resource limits, workload placement, and client timeouts fixed unless they
  are the independent variable.
- Run the primary comparison with VPC CNI NetworkPolicy disabled because gateway
  coexistence is not implemented. Scope conclusions accordingly; record a
  policy-enabled `cluster-dns`/`node-local` compatibility subset as external
  validity evidence, not as a three-way performance comparison.
- Remove NodeLocal and gateway components completely for the clean
  `cluster-dns` arm.
- Never equate gateway bypass with an uninstalled baseline.
- Record and verify the active Corefile and mechanism before every run.
- Randomize mechanism order within repeated blocks.
- Use at least 10 valid blocks for headline cells and at least 5 for secondary
  cells.
- Use run/block-level confidence intervals; do not treat millions of queries
  from one run as independent experimental repetitions.
- Predeclare exclusion criteria and retain excluded raw runs.

## Existing evidence and gaps

[`benchmark-diversity.md`](benchmark-diversity.md) provides useful preliminary
results from 1,000 Pods and 40 `m5.large` nodes. It demonstrates a large
answer-cardinality difference and lower median latency in one S3 workload.
Treat it as motivation, not confirmatory evidence, because it has:

- one cluster, region, name, and run;
- no NodeLocal DNSCache arm;
- a shared-cache versus non-gateway-cache confounder;
- no CPU, memory, cache-hit, kernel conntrack, or BPF runtime measurements;
- unique-IP union rather than a frequency distribution;
- errors excluded from latency percentiles;
- a synchronous HTTP report after each lookup;
- `LookupHost` rather than controlled QTYPE/transport traffic;
- gateway bypass rather than a fully detached clean baseline;
- variable coordinated-burst sample counts.

Keep `test/loadgen/` for reproducing the preliminary result. Build a separate,
pinned paper harness rather than silently changing the historical benchmark.

## Publication figures and tables

Produce at least:

1. architecture and query-path diagram;
2. p50/p95/p99 latency versus offered QPS;
3. attained QPS under the declared SLO;
4. CPU time per query and cluster-total memory;
5. cache-hit ratio and upstream amplification;
6. latency/resource scaling versus Pod and node count;
7. answer and connection concentration distributions;
8. Linux/BPF state occupancy versus concurrency;
9. failure timeline with loss, fallback, and recovery;
10. protocol and IP-family correctness table.

Publish the environment manifest, raw run manifests, analysis code, confidence
intervals, and exclusion log with the paper artifacts.

## Sources

- Repository design: [`design.md`](design.md)
- Existing scale benchmark: [`benchmark-diversity.md`](benchmark-diversity.md)
- Live functional validation: [`testing.md`](testing.md)
- [Kubernetes NodeLocal DNSCache documentation](https://kubernetes.io/docs/tasks/administer-cluster/nodelocaldns)
- [NodeLocal DNSCache KEP-1024](https://github.com/kubernetes/enhancements/blob/master/keps/sig-network/1024-nodelocal-cache-dns/README.md)
- [Kubernetes DNS performance tests](https://github.com/kubernetes/perf-tests/blob/master/dns/README.md)
- [CoreDNS scaling guidance](https://github.com/coredns/deployment/blob/master/kubernetes/Scaling_CoreDNS.md)
- [CoreDNS cache metrics](https://coredns.io/plugins/cache/)
- [CoreDNS Prometheus metrics](https://coredns.io/plugins/metrics/)
- [Route 53 VPC Resolver availability and scaling](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-availability-scaling.html)
