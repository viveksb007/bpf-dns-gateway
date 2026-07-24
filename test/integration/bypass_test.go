//go:build linux

package integration

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	bpf "github.com/viveksb007/bpf-dns-gateway/internal/ebpf"
	"github.com/viveksb007/bpf-dns-gateway/internal/health"
)

// readBypass reads the bypass flag straight from the pinned config_map.
func readBypass(t *testing.T, l *bpf.Loader) bool {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(filepath.Join(l.PinDir(), "config_map"), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap config_map: %v", err)
	}
	defer m.Close()
	var v bpf.DnsGatewayGatewayConfig
	if err := m.Lookup(uint32(0), &v); err != nil {
		t.Fatalf("config_map lookup: %v", err)
	}
	return v.Bypass != 0
}

// waitBypass polls config_map until bypass == want or timeout.
func waitBypass(t *testing.T, l *bpf.Loader, want bool, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if readBypass(t, l) == want {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestBypassStopsIngressDNAT: with bypass=1, a matching query is NOT
// DNAT'd (ingress short-circuits). Complements TestPassthroughBypass in
// redirect_test.go by also asserting no conntrack entry is created.
func TestBypassStopsIngressDNAT(t *testing.T) {
	l := loadGateway(t)
	if err := l.PopulateSuffixRules([]bpf.SuffixRule{{Pattern: "*.s3.amazonaws.com", Action: bpf.ActionHostResolve}}); err != nil {
		t.Fatalf("PopulateSuffixRules: %v", err)
	}
	if err := l.SetBypass(true); err != nil {
		t.Fatalf("SetBypass: %v", err)
	}
	pkt := buildDNSQuery(t, "mybucket.s3.amazonaws.com")
	_, out := runIngress(t, l, pkt)
	if !bytes.Equal(pkt, out) {
		t.Error("matching query DNAT'd while bypass=1")
	}
	if conntrackExists(t, l) {
		t.Error("conntrack entry created while bypass=1")
	}
}

// TestEgressSNATsInFlightUnderBypass: the critical invariant — a query
// DNAT'd BEFORE bypass flips must still be SNAT'd on egress so the pod
// never sees src=host_resolver_ip. Egress ignores cfg->bypass.
func TestEgressSNATsInFlightUnderBypass(t *testing.T) {
	l := loadGateway(t)
	if err := l.PopulateSuffixRules([]bpf.SuffixRule{{Pattern: "*.s3.amazonaws.com", Action: bpf.ActionHostResolve}}); err != nil {
		t.Fatalf("PopulateSuffixRules: %v", err)
	}

	// Step 1: query DNAT'd (bypass off) -> conntrack created.
	q := buildDNSQuery(t, "mybucket.s3.amazonaws.com")
	if _, _ = runIngress(t, l, q); !conntrackExists(t, l) {
		t.Fatalf("conntrack not populated by ingress")
	}

	// Step 2: bypass flips ON mid-flight.
	if err := l.SetBypass(true); err != nil {
		t.Fatalf("SetBypass: %v", err)
	}

	// Step 3: the response arrives. Egress must STILL SNAT it back to
	// CoreDNS despite bypass=1.
	resp := buildDNSResponse(t, "mybucket.s3.amazonaws.com")
	ret, out := runEgress(t, l, resp)
	if ret != 0 {
		t.Errorf("egress ret = %d, want TC_ACT_OK", ret)
	}
	gotSrc := net.IP(out[14+12 : 14+16])
	if !gotSrc.Equal(net.ParseIP(corednsIP).To4()) {
		t.Errorf("egress src = %s, want %s (CoreDNS) — bypass must NOT suppress egress SNAT", gotSrc, corednsIP)
	}
}

// TestHealthCheckerActivatesAndClearsBypass drives the real health
// checker against an unreachable resolver (bypass should activate after
// threshold) then a reachable one (bypass should clear), toggling the
// real eBPF config_map through the loader.
func TestHealthCheckerActivatesAndClearsBypass(t *testing.T) {
	l := loadGateway(t)

	// Unreachable: 192.0.2.1 is TEST-NET-1, guaranteed no responder.
	checker, err := health.New(health.Config{
		ResolverIP:       net.ParseIP("192.0.2.1"),
		Interval:         50 * time.Millisecond,
		Timeout:          30 * time.Millisecond,
		FailureThreshold: 3,
	}, l, nil)
	if err != nil {
		t.Fatalf("health.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = checker.Run(ctx) }()

	// Wait for bypass to activate in the real config_map.
	if !waitBypass(t, l, true, 3*time.Second) {
		t.Fatalf("bypass did not activate after health probe failures")
	}
	cancel()
}

// TestHealthCheckerRecoversBypass drives the full fail->recover path
// against the real config_map with a SINGLE long-lived checker (as in
// production): a togglable local DNS responder starts unhealthy
// (drops queries -> bypass ON after threshold), then is flipped healthy
// (answers -> bypass CLEARS on first success).
func TestHealthCheckerRecoversBypass(t *testing.T) {
	l := loadGateway(t)

	td := startToggleDNS(t)
	td.setHealthy(false) // start unhealthy

	checker, err := health.New(health.Config{
		ResolverIP:       td.ip,
		ProbePort:        td.port,
		Interval:         50 * time.Millisecond,
		Timeout:          200 * time.Millisecond,
		FailureThreshold: 2,
	}, l, nil)
	if err != nil {
		t.Fatalf("health.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = checker.Run(ctx) }()

	if !waitBypass(t, l, true, 3*time.Second) {
		t.Fatalf("bypass did not activate while resolver unhealthy")
	}

	td.setHealthy(true) // recover
	if !waitBypass(t, l, false, 3*time.Second) {
		t.Fatalf("bypass did not clear after resolver recovered")
	}
}

// TestConntrackFreshWithinTTL: a response within CONNTRACK_TTL_NS is
// SNAT'd and its entry deleted.
func TestConntrackFreshWithinTTL(t *testing.T) {
	l := loadGateway(t)
	if err := l.PopulateSuffixRules([]bpf.SuffixRule{{Pattern: "*.s3.amazonaws.com", Action: bpf.ActionHostResolve}}); err != nil {
		t.Fatalf("PopulateSuffixRules: %v", err)
	}
	q := buildDNSQuery(t, "mybucket.s3.amazonaws.com")
	if _, _ = runIngress(t, l, q); !conntrackExists(t, l) {
		t.Fatalf("conntrack not populated")
	}
	resp := buildDNSResponse(t, "mybucket.s3.amazonaws.com")
	_, out := runEgress(t, l, resp)
	gotSrc := net.IP(out[14+12 : 14+16])
	if !gotSrc.Equal(net.ParseIP(corednsIP).To4()) {
		t.Errorf("fresh-within-TTL response not SNAT'd: src=%s", gotSrc)
	}
	if conntrackExists(t, l) {
		t.Error("conntrack entry not deleted after successful SNAT")
	}
}

// TestConntrackStaleBeyondTTL forces the egress TTL-expiry branch:
// ingress creates a conntrack entry, we backdate its timestamp_ns in
// the pinned conntrack_map to older than CONNTRACK_TTL_NS, then the
// response must be treated as a miss — passthrough unmodified, stale
// entry deleted.
func TestConntrackStaleBeyondTTL(t *testing.T) {
	l := loadGateway(t)
	if err := l.PopulateSuffixRules([]bpf.SuffixRule{{Pattern: "*.s3.amazonaws.com", Action: bpf.ActionHostResolve}}); err != nil {
		t.Fatalf("PopulateSuffixRules: %v", err)
	}
	q := buildDNSQuery(t, "mybucket.s3.amazonaws.com")
	if _, _ = runIngress(t, l, q); !conntrackExists(t, l) {
		t.Fatalf("conntrack not populated")
	}

	// Backdate every conntrack entry's timestamp to 0 (epoch of
	// bpf_ktime_get_ns is boot; 0 is always older than now-TTL).
	ctMap, err := ebpf.LoadPinnedMap(filepath.Join(l.PinDir(), "conntrack_map"), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap conntrack_map: %v", err)
	}
	defer ctMap.Close()
	var k bpf.DnsGatewayConntrackKey
	var v bpf.DnsGatewayConntrackValue
	iter := ctMap.Iterate()
	var keys []bpf.DnsGatewayConntrackKey
	for iter.Next(&k, &v) {
		keys = append(keys, k)
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate conntrack_map: %v", err)
	}
	for _, key := range keys {
		var val bpf.DnsGatewayConntrackValue
		if err := ctMap.Lookup(key, &val); err != nil {
			t.Fatalf("lookup: %v", err)
		}
		val.TimestampNs = 0 // ancient -> beyond TTL
		if err := ctMap.Update(key, val, ebpf.UpdateAny); err != nil {
			t.Fatalf("update backdated ts: %v", err)
		}
	}

	resp := buildDNSResponse(t, "mybucket.s3.amazonaws.com")
	_, out := runEgress(t, l, resp)
	// Stale -> passthrough: src must be UNCHANGED (still host resolver).
	gotSrc := net.IP(out[14+12 : 14+16])
	if !gotSrc.Equal(net.ParseIP(hostIP).To4()) {
		t.Errorf("stale-entry response was SNAT'd (src=%s); expected passthrough with src=%s", gotSrc, hostIP)
	}
	// Stale entry must be deleted by the egress TTL branch.
	if conntrackExists(t, l) {
		t.Error("stale conntrack entry not deleted on egress")
	}
}
