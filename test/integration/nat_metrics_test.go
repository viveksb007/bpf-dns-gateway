//go:build linux

package integration

import (
	"net"
	"testing"

	bpf "github.com/viveksb007/bpf-dns-gateway/internal/ebpf"
)

// Regression coverage for the checked NAT rewrite path (design.md §9.1
// fix): every bpf_skb_store_bytes / bpf_l{3,4}_csum_replace return is
// now checked, with revert + METRIC_NAT_ERROR on failure. A helper
// failure cannot be forced from userspace (it requires pathological
// offsets), so this test proves the inverse property: the checked path
// introduces no false positives — a full DNAT + SNAT round trip
// completes with both NAT-failure counters at exactly 0 while the
// success counters advance.
func TestNATRewrite_NoErrorsOnRoundTrip(t *testing.T) {
	l := loadGateway(t)
	if err := l.PopulateSuffixRules([]bpf.SuffixRule{{Pattern: "*.s3.amazonaws.com", Action: bpf.ActionHostResolve}}); err != nil {
		t.Fatalf("PopulateSuffixRules: %v", err)
	}

	before, err := l.ReadMetrics()
	if err != nil {
		t.Fatalf("ReadMetrics before: %v", err)
	}

	const rounds = 50
	for range rounds {
		// Ingress DNAT (rewrites daddr + both checksums)...
		q := buildDNSQuery(t, "mybucket.s3.amazonaws.com")
		_, out := runIngress(t, l, q)
		if got := net.IP(out[14+16 : 14+20]); !got.Equal(net.ParseIP(hostIP).To4()) {
			t.Fatalf("DNAT did not rewrite dst: got %s", got)
		}
		// ...then egress SNAT of the matching response (rewrites saddr).
		resp := buildDNSResponse(t, "mybucket.s3.amazonaws.com")
		_, out = runEgress(t, l, resp)
		if got := net.IP(out[14+12 : 14+16]); !got.Equal(net.ParseIP(corednsIP).To4()) {
			t.Fatalf("SNAT did not rewrite src: got %s", got)
		}
	}

	after, err := l.ReadMetrics()
	if err != nil {
		t.Fatalf("ReadMetrics after: %v", err)
	}

	if d := after[bpf.MetricNatError] - before[bpf.MetricNatError]; d != 0 {
		t.Errorf("nat_errors_total advanced by %d on healthy round trips, want 0", d)
	}
	if d := after[bpf.MetricNatRevertFail] - before[bpf.MetricNatRevertFail]; d != 0 {
		t.Errorf("nat_revert_failures_total advanced by %d, want 0", d)
	}
	// Success counters must actually have moved (guards against the
	// checked path silently short-circuiting).
	if d := after[bpf.MetricSuffixMatch] - before[bpf.MetricSuffixMatch]; d != rounds {
		t.Errorf("suffix_match_total advanced by %d, want %d", d, rounds)
	}
	if d := after[bpf.MetricEgressSnat] - before[bpf.MetricEgressSnat]; d != rounds {
		t.Errorf("egress_snat_total advanced by %d, want %d", d, rounds)
	}
}
