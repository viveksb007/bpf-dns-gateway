// Package metrics exposes the eBPF datapath counters and controller
// state as Prometheus metrics.
//
// The datapath counters live in a per-CPU BPF array map; the collector
// reads + sums them on every scrape (pull model) so there is no
// background polling goroutine and no staleness window. Controller and
// health state are read through small provider interfaces so this
// package stays decoupled from the ebpf / controller / health packages.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	bpf "github.com/viveksb007/bpf-dns-gateway/internal/ebpf"
)

const namespace = "bpf_dns_gateway"

// DatapathSource provides the per-CPU eBPF counters and the loaded
// suffix-rule count. The ebpf.Loader satisfies it.
type DatapathSource interface {
	ReadMetrics() (bpf.MetricSnapshot, error)
	CountSuffixRules() (int, error)
}

// AttachSource reports how many interfaces are currently attached. The
// ebpf.AttachManager satisfies it.
type AttachSource interface {
	AttachedCount() int
}

// HealthSource reports health-checker state. The health.Checker
// satisfies it.
type HealthSource interface {
	ProbeFailures() uint64
	BypassActive() bool
}

// Collector implements prometheus.Collector. All values are read live on
// each scrape.
type Collector struct {
	datapath DatapathSource
	attach   AttachSource
	health   HealthSource
	logger   logger

	// Datapath counter descriptors, indexed by ebpf.MetricID.
	datapathDescs map[bpf.MetricID]*prometheus.Desc

	attachedVeths  *prometheus.Desc
	bypassActive   *prometheus.Desc
	suffixRules    *prometheus.Desc
	healthFailures *prometheus.Desc

	scrapeErrors prometheus.Counter
}

// logger is the minimal logging surface (slog.Logger satisfies it).
type logger interface {
	Error(msg string, args ...any)
}

// datapathMetric maps an eBPF metric ID to its Prometheus name + help.
type datapathMetric struct {
	id   bpf.MetricID
	name string
	help string
}

// datapathMetrics is the fixed mapping from eBPF counter IDs to the
// exported Prometheus names (design.md §10.1). Order is irrelevant.
var datapathMetrics = []datapathMetric{
	{bpf.MetricTotalPackets, "ingress_total_packets", "Total packets seen on TC ingress."},
	{bpf.MetricDNSQueries, "dns_queries_total", "DNS queries to CoreDNS observed on ingress."},
	{bpf.MetricSuffixMatch, "suffix_match_total", "DNS queries that matched a suffix rule (either action)."},
	{bpf.MetricSuffixNoMatch, "suffix_no_match_total", "DNS queries matching no rule (default action applied)."},
	{bpf.MetricRedirected, "redirected_total", "DNS queries DNAT'd to the VPC resolver (rule or default action)."},
	{bpf.MetricClusterResolved, "cluster_resolved_total", "DNS queries deliberately kept on CoreDNS (rule or default action)."},
	{bpf.MetricBypassActive, "bypass_packets_total", "Packets passed through because the bypass flag was set."},
	{bpf.MetricParseError, "parse_errors_total", "DNS parse failures (compression ptr, QDCOUNT!=1, malformed)."},
	{bpf.MetricEgressSnat, "egress_snat_total", "Response packets SNAT'd back to CoreDNS."},
	{bpf.MetricEgressConntrackMiss, "egress_conntrack_miss_total", "VPC-DNS responses with no/expired conntrack entry."},
	{bpf.MetricEgressTotal, "egress_total_packets", "Total packets seen on TC egress."},
	{bpf.MetricNatError, "nat_errors_total", "NAT rewrite helper failures; packet reverted and passed through unmodified."},
	{bpf.MetricNatRevertFail, "nat_revert_failures_total", "NAT failures where the revert also failed (packet possibly inconsistent). Should stay 0."},
}

// New builds a Collector. Any of attach/health may be nil (their
// metrics are simply not emitted), but datapath is required.
func New(datapath DatapathSource, attach AttachSource, health HealthSource, lg logger) *Collector {
	descs := make(map[bpf.MetricID]*prometheus.Desc, len(datapathMetrics))
	for _, m := range datapathMetrics {
		descs[m.id] = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", m.name),
			m.help, nil, nil,
		)
	}
	return &Collector{
		datapath:      datapath,
		attach:        attach,
		health:        health,
		logger:        lg,
		datapathDescs: descs,
		attachedVeths: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "attached_veths"),
			"Number of veth interfaces our programs are attached to.", nil, nil),
		bypassActive: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "bypass_active"),
			"Whether bypass is currently active (1) or not (0).", nil, nil),
		suffixRules: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "suffix_rules_loaded"),
			"Number of suffix rules loaded into the BPF map.", nil, nil),
		// design.md §10.1 names this metric without a _total suffix.
		healthFailures: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "health_check_failures"),
			"Cumulative count of failed VPC DNS health probes.", nil, nil),
		scrapeErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "scrape_errors_total",
			Help:      "Cumulative count of errors reading BPF maps during a scrape.",
		}),
	}
}

// Describe implements prometheus.Collector. We send descriptors so the
// registry can detect duplicate registration, but the collector is
// effectively unchecked (values vary per scrape).
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.datapathDescs {
		ch <- d
	}
	ch <- c.attachedVeths
	ch <- c.bypassActive
	ch <- c.suffixRules
	ch <- c.healthFailures
	ch <- c.scrapeErrors.Desc()
}

// Collect implements prometheus.Collector. Reads all sources live.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.collectDatapath(ch)
	c.collectController(ch)
	ch <- c.scrapeErrors
}

func (c *Collector) collectDatapath(ch chan<- prometheus.Metric) {
	snap, err := c.datapath.ReadMetrics()
	if err != nil {
		c.recordScrapeError("read metrics map", err)
		return
	}
	for _, m := range datapathMetrics {
		ch <- prometheus.MustNewConstMetric(
			c.datapathDescs[m.id],
			prometheus.CounterValue,
			float64(snap[m.id]),
		)
	}
}

func (c *Collector) collectController(ch chan<- prometheus.Metric) {
	if n, err := c.datapath.CountSuffixRules(); err != nil {
		c.recordScrapeError("count suffix rules", err)
	} else {
		ch <- prometheus.MustNewConstMetric(c.suffixRules, prometheus.GaugeValue, float64(n))
	}

	if c.attach != nil {
		ch <- prometheus.MustNewConstMetric(
			c.attachedVeths, prometheus.GaugeValue, float64(c.attach.AttachedCount()))
	}

	if c.health != nil {
		bypass := 0.0
		if c.health.BypassActive() {
			bypass = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.bypassActive, prometheus.GaugeValue, bypass)
		ch <- prometheus.MustNewConstMetric(
			c.healthFailures, prometheus.CounterValue, float64(c.health.ProbeFailures()))
	}
}

func (c *Collector) recordScrapeError(what string, err error) {
	c.scrapeErrors.Inc()
	if c.logger != nil {
		c.logger.Error("metrics scrape error", "what", what, "err", err)
	}
}
