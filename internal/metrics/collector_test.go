package metrics

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	bpf "github.com/viveksb007/bpf-dns-gateway/internal/ebpf"
)

type fakeDatapath struct {
	snap       bpf.MetricSnapshot
	rules      int
	readErr    error
	countErr   error
	readCalls  int
	countCalls int
}

func (f *fakeDatapath) ReadMetrics() (bpf.MetricSnapshot, error) {
	f.readCalls++
	return f.snap, f.readErr
}

func (f *fakeDatapath) CountSuffixRules() (int, error) {
	f.countCalls++
	return f.rules, f.countErr
}

type fakeAttach struct{ n int }

func (f *fakeAttach) AttachedCount() int { return f.n }

type fakeHealth struct {
	failures uint64
	bypass   bool
}

func (f *fakeHealth) ProbeFailures() uint64 { return f.failures }
func (f *fakeHealth) BypassActive() bool    { return f.bypass }

func registerAndGather(t *testing.T, c *Collector) string {
	t.Helper()
	reg := prometheus.NewRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("Register: %v", err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var sb strings.Builder
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			var v float64
			switch {
			case m.GetCounter() != nil:
				v = m.GetCounter().GetValue()
			case m.GetGauge() != nil:
				v = m.GetGauge().GetValue()
			}
			fmt.Fprintf(&sb, "%s %g\n", mf.GetName(), v)
		}
	}
	return sb.String()
}

func TestCollector_AllMetricsPresent(t *testing.T) {
	dp := &fakeDatapath{rules: 5}
	dp.snap[bpf.MetricTotalPackets] = 100
	dp.snap[bpf.MetricDNSQueries] = 40
	dp.snap[bpf.MetricSuffixMatch] = 12
	dp.snap[bpf.MetricEgressSnat] = 11
	dp.snap[bpf.MetricNatError] = 2
	dp.snap[bpf.MetricNatRevertFail] = 1
	at := &fakeAttach{n: 7}
	he := &fakeHealth{failures: 3, bypass: true}

	c := New(dp, at, he, nil)
	out := registerAndGather(t, c)

	wants := []string{
		"bpf_dns_gateway_ingress_total_packets 100",
		"bpf_dns_gateway_dns_queries_total 40",
		"bpf_dns_gateway_suffix_match_total 12",
		"bpf_dns_gateway_egress_snat_total 11",
		"bpf_dns_gateway_nat_errors_total 2",
		"bpf_dns_gateway_nat_revert_failures_total 1",
		"bpf_dns_gateway_attached_veths 7",
		"bpf_dns_gateway_bypass_active 1",
		"bpf_dns_gateway_suffix_rules_loaded 5",
		"bpf_dns_gateway_health_check_failures 3",
		"bpf_dns_gateway_scrape_errors_total 0",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

func TestCollector_BypassZeroWhenInactive(t *testing.T) {
	dp := &fakeDatapath{}
	he := &fakeHealth{bypass: false}
	c := New(dp, &fakeAttach{}, he, nil)
	out := registerAndGather(t, c)
	if !strings.Contains(out, "bpf_dns_gateway_bypass_active 0") {
		t.Errorf("expected bypass_active 0:\n%s", out)
	}
}

func TestCollector_ReadMetricsErrorIncrementsScrapeErrors(t *testing.T) {
	dp := &fakeDatapath{readErr: fmt.Errorf("boom")}
	c := New(dp, &fakeAttach{}, &fakeHealth{}, nil)
	out := registerAndGather(t, c)
	// Datapath counters absent, scrape_errors incremented.
	if strings.Contains(out, "bpf_dns_gateway_ingress_total_packets") {
		t.Errorf("datapath metrics emitted despite read error:\n%s", out)
	}
	if !strings.Contains(out, "bpf_dns_gateway_scrape_errors_total 1") {
		t.Errorf("scrape_errors not incremented:\n%s", out)
	}
}

func TestCollector_CountErrorStillEmitsOthers(t *testing.T) {
	dp := &fakeDatapath{countErr: fmt.Errorf("boom")}
	dp.snap[bpf.MetricTotalPackets] = 9
	c := New(dp, &fakeAttach{n: 2}, &fakeHealth{}, nil)
	out := registerAndGather(t, c)
	if !strings.Contains(out, "bpf_dns_gateway_ingress_total_packets 9") {
		t.Errorf("datapath metric missing after count error:\n%s", out)
	}
	if strings.Contains(out, "bpf_dns_gateway_suffix_rules_loaded") {
		t.Errorf("suffix_rules_loaded emitted despite count error:\n%s", out)
	}
	if !strings.Contains(out, "bpf_dns_gateway_scrape_errors_total 1") {
		t.Errorf("scrape_errors not incremented:\n%s", out)
	}
}

func TestCollector_NilAttachAndHealthOmitted(t *testing.T) {
	dp := &fakeDatapath{rules: 1}
	c := New(dp, nil, nil, nil)
	out := registerAndGather(t, c)
	if strings.Contains(out, "bpf_dns_gateway_attached_veths") {
		t.Errorf("attached_veths emitted with nil attach source:\n%s", out)
	}
	if strings.Contains(out, "bpf_dns_gateway_bypass_active") {
		t.Errorf("bypass_active emitted with nil health source:\n%s", out)
	}
	// suffix_rules still present (datapath source).
	if !strings.Contains(out, "bpf_dns_gateway_suffix_rules_loaded 1") {
		t.Errorf("suffix_rules_loaded missing:\n%s", out)
	}
}
