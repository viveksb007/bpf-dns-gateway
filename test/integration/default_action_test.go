//go:build linux

package integration

import (
	"bytes"
	"net"
	"testing"

	bpf "github.com/viveksb007/bpf-dns-gateway/internal/ebpf"
)

// Task 24 (design.md §6.2/§8): defaultAction=host-resolve ("non-cluster"
// mode, issue #1) — everything redirects to the VPC resolver except
// cluster-resolve rules.

// hostResolveLoader configures the gateway in non-cluster mode with the
// standard cluster-suffix rules.
func hostResolveLoader(t *testing.T) *bpf.Loader {
	t.Helper()
	l := loadGateway(t)
	if err := l.PopulateConfig(bpf.Config{
		CorednsIP:      net.ParseIP(corednsIP),
		HostResolverIP: net.ParseIP(hostIP),
		DefaultAction:  bpf.ActionHostResolve,
	}); err != nil {
		t.Fatalf("PopulateConfig: %v", err)
	}
	if err := l.PopulateSuffixRules([]bpf.SuffixRule{
		{Pattern: "*.cluster.local", Action: bpf.ActionClusterResolve},
		{Pattern: "*.in-addr.arpa", Action: bpf.ActionClusterResolve},
	}); err != nil {
		t.Fatalf("PopulateSuffixRules: %v", err)
	}
	return l
}

// A query matching no rule must be DNAT'd to the VPC resolver (the
// inverse of the allowlist default).
func TestDefaultHostResolve_NonMatchRedirected(t *testing.T) {
	l := hostResolveLoader(t)

	pkt := buildDNSQuery(t, "mybucket.s3.amazonaws.com")
	deltaRedir := metricDelta(t, l, bpf.MetricRedirected, func() {
		_, out := runIngress(t, l, pkt)
		gotDst := net.IP(out[14+16 : 14+20])
		if !gotDst.Equal(net.ParseIP(hostIP).To4()) {
			t.Errorf("dst IP = %s, want %s (VPC resolver)", gotDst, hostIP)
		}
	})
	if deltaRedir != 1 {
		t.Errorf("redirected_total delta = %d, want 1", deltaRedir)
	}
	if !conntrackExists(t, l) {
		t.Error("conntrack entry missing after default-action DNAT")
	}
}

// Cluster service discovery must stay on CoreDNS untouched.
func TestDefaultHostResolve_ClusterSuffixPassthrough(t *testing.T) {
	l := hostResolveLoader(t)

	pkt := buildDNSQuery(t, "kubernetes.default.svc.cluster.local")
	deltaCluster := metricDelta(t, l, bpf.MetricClusterResolved, func() {
		_, out := runIngress(t, l, pkt)
		if !bytes.Equal(pkt, out) {
			t.Error("cluster.local query was modified in host-resolve default mode")
		}
	})
	if deltaCluster != 1 {
		t.Errorf("cluster_resolved_total delta = %d, want 1", deltaCluster)
	}
	if conntrackExists(t, l) {
		t.Error("conntrack entry created for cluster-resolve query")
	}
}

// Reverse lookups (pod/service PTR records served by kube-dns) must
// stay on CoreDNS.
func TestDefaultHostResolve_ReverseLookupPassthrough(t *testing.T) {
	l := hostResolveLoader(t)

	pkt := buildDNSQuery(t, "10.0.100.10.in-addr.arpa")
	_, out := runIngress(t, l, pkt)
	if !bytes.Equal(pkt, out) {
		t.Error("in-addr.arpa query was modified in host-resolve default mode")
	}
	if conntrackExists(t, l) {
		t.Error("conntrack entry created for reverse lookup")
	}
}

// Most-specific match wins: a broad host-resolve rule plus a narrower
// cluster-resolve rule — the S3 name must stay on CoreDNS because the
// label walk tries the longest suffix first (design.md §6.2).
func TestDefaultHostResolve_MostSpecificRuleWins(t *testing.T) {
	l := loadGateway(t)
	if err := l.PopulateConfig(bpf.Config{
		CorednsIP:      net.ParseIP(corednsIP),
		HostResolverIP: net.ParseIP(hostIP),
		DefaultAction:  bpf.ActionClusterResolve,
	}); err != nil {
		t.Fatalf("PopulateConfig: %v", err)
	}
	if err := l.PopulateSuffixRules([]bpf.SuffixRule{
		{Pattern: "*.amazonaws.com", Action: bpf.ActionHostResolve},
		{Pattern: "*.s3.amazonaws.com", Action: bpf.ActionClusterResolve},
	}); err != nil {
		t.Fatalf("PopulateSuffixRules: %v", err)
	}

	// S3 name: both rules match; the more specific cluster-resolve
	// must win → passthrough.
	pkt := buildDNSQuery(t, "mybucket.s3.amazonaws.com")
	_, out := runIngress(t, l, pkt)
	if !bytes.Equal(pkt, out) {
		t.Error("specific cluster-resolve rule did not override broader host-resolve rule")
	}

	// Non-S3 amazonaws.com name: only the broad rule matches → DNAT.
	pkt = buildDNSQuery(t, "sqs.us-west-2.amazonaws.com")
	_, out = runIngress(t, l, pkt)
	gotDst := net.IP(out[14+16 : 14+20])
	if !gotDst.Equal(net.ParseIP(hostIP).To4()) {
		t.Errorf("broad host-resolve rule not applied: dst = %s, want %s", gotDst, hostIP)
	}
}

// Bypass must protect the cluster in host-resolve default mode too:
// with bypass=1 nothing is redirected, not even default-action queries.
func TestDefaultHostResolve_BypassPassthrough(t *testing.T) {
	l := hostResolveLoader(t)
	if err := l.SetBypass(true); err != nil {
		t.Fatalf("SetBypass: %v", err)
	}

	pkt := buildDNSQuery(t, "mybucket.s3.amazonaws.com")
	_, out := runIngress(t, l, pkt)
	if !bytes.Equal(pkt, out) {
		t.Error("query was DNAT'd despite bypass=1 in host-resolve default mode")
	}
	if conntrackExists(t, l) {
		t.Error("conntrack entry created despite bypass")
	}
}

// SNAT of a response to a default-action-redirected query works exactly
// as for rule-matched queries (egress is action-agnostic: conntrack
// driven).
func TestDefaultHostResolve_ResponseSNAT(t *testing.T) {
	l := hostResolveLoader(t)

	pkt := buildDNSQuery(t, "mybucket.s3.amazonaws.com")
	if _, _ = runIngress(t, l, pkt); !conntrackExists(t, l) {
		t.Fatalf("conntrack not populated by default-action DNAT")
	}

	resp := buildDNSResponse(t, "mybucket.s3.amazonaws.com")
	_, out := runEgress(t, l, resp)
	gotSrc := net.IP(out[14+12 : 14+16])
	if !gotSrc.Equal(net.ParseIP(corednsIP).To4()) {
		t.Errorf("egress src = %s, want %s (CoreDNS)", gotSrc, corednsIP)
	}
	if conntrackExists(t, l) {
		t.Error("conntrack entry not deleted after SNAT")
	}
}
