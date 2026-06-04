//go:build linux

package ebpf

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

// requireRootBPF loads a Loader pointed at a temp pin dir on bpffs.
// Skips if not root or if /sys/fs/bpf is unavailable.
func requireRootBPF(t *testing.T) *Loader {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root to load eBPF")
	}
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		t.Skipf("bpffs not mounted at /sys/fs/bpf: %v", err)
	}
	pinDir := filepath.Join("/sys/fs/bpf", "dns-gateway-test-"+t.Name())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	l, err := New(pinDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		_ = l.Close()
		_ = l.Unpin()
	})
	return l
}

func TestPopulateConfig(t *testing.T) {
	l := requireRootBPF(t)
	cfg := Config{
		CorednsIP:      net.ParseIP("10.100.0.10"),
		HostResolverIP: net.ParseIP("10.0.0.2"),
	}
	if err := l.PopulateConfig(cfg); err != nil {
		t.Fatalf("PopulateConfig: %v", err)
	}
	var got DnsGatewayGatewayConfig
	if err := l.objs.ConfigMap.Lookup(uint32(0), &got); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	// Wire bytes for 10.100.0.10 = 0x0a 0x64 0x00 0x0a; the host uint32
	// must serialize to those bytes regardless of host endianness.
	wantCoreDNS := nativeUint32IP(net.IPv4(10, 100, 0, 10).To4())
	if got.CorednsIp != wantCoreDNS {
		t.Errorf("corednsIp = %#x, want %#x", got.CorednsIp, wantCoreDNS)
	}
	wantHost := nativeUint32IP(net.IPv4(10, 0, 0, 2).To4())
	if got.HostResolverIp != wantHost {
		t.Errorf("hostResolverIp = %#x, want %#x", got.HostResolverIp, wantHost)
	}
	if got.DnsPort != dnsPort53 {
		t.Errorf("dnsPort = %#x, want %#x", got.DnsPort, dnsPort53)
	}
	if got.Bypass != 0 {
		t.Errorf("bypass = %d, want 0", got.Bypass)
	}
}

func TestSetBypass(t *testing.T) {
	l := requireRootBPF(t)
	cfg := Config{
		CorednsIP:      net.ParseIP("10.100.0.10"),
		HostResolverIP: net.ParseIP("10.0.0.2"),
	}
	if err := l.PopulateConfig(cfg); err != nil {
		t.Fatalf("PopulateConfig: %v", err)
	}
	if err := l.SetBypass(true); err != nil {
		t.Fatalf("SetBypass(true): %v", err)
	}
	var got DnsGatewayGatewayConfig
	if err := l.objs.ConfigMap.Lookup(uint32(0), &got); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Bypass != 1 {
		t.Errorf("bypass after SetBypass(true) = %d, want 1", got.Bypass)
	}
	// CoreDNS IP must be untouched.
	wantCoreDNS := nativeUint32IP(net.IPv4(10, 100, 0, 10).To4())
	if got.CorednsIp != wantCoreDNS {
		t.Errorf("corednsIp drifted: got %#x, want %#x", got.CorednsIp, wantCoreDNS)
	}
	if err := l.SetBypass(false); err != nil {
		t.Fatalf("SetBypass(false): %v", err)
	}
	if err := l.objs.ConfigMap.Lookup(uint32(0), &got); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Bypass != 0 {
		t.Errorf("bypass after SetBypass(false) = %d, want 0", got.Bypass)
	}
}

func TestPopulateSuffixRules_AddDelete(t *testing.T) {
	l := requireRootBPF(t)

	patterns := []string{
		"*.s3.amazonaws.com",
		"*.s3.us-west-2.amazonaws.com",
	}
	if err := l.PopulateSuffixRules(patterns); err != nil {
		t.Fatalf("PopulateSuffixRules: %v", err)
	}
	if n, err := l.CountSuffixRules(); err != nil || n != 2 {
		t.Fatalf("count after add: n=%d err=%v", n, err)
	}

	// Reconcile to a different set: drop one, add one.
	patterns2 := []string{
		"*.s3.amazonaws.com",
		"*.dkr.ecr.us-west-2.amazonaws.com",
	}
	if err := l.PopulateSuffixRules(patterns2); err != nil {
		t.Fatalf("PopulateSuffixRules reconcile: %v", err)
	}
	if n, err := l.CountSuffixRules(); err != nil || n != 2 {
		t.Fatalf("count after reconcile: n=%d err=%v", n, err)
	}
	// Empty reconcile clears the map.
	if err := l.PopulateSuffixRules(nil); err != nil {
		t.Fatalf("PopulateSuffixRules empty: %v", err)
	}
	if n, err := l.CountSuffixRules(); err != nil || n != 0 {
		t.Fatalf("count after clear: n=%d err=%v", n, err)
	}
}

func TestPopulateSuffixRules_RejectsNonWildcard(t *testing.T) {
	l := requireRootBPF(t)
	err := l.PopulateSuffixRules([]string{"s3.amazonaws.com"})
	if err == nil {
		t.Fatalf("expected error rejecting non-wildcard pattern")
	}
}

func TestPopulateSuffixRules_RejectsInteriorWildcard(t *testing.T) {
	l := requireRootBPF(t)
	cases := []string{
		"*.*.amazonaws.com",
		"*.s3.*.amazonaws.com",
		"*.foo*bar.amazonaws.com",
	}
	for _, p := range cases {
		if err := l.PopulateSuffixRules([]string{p}); err == nil {
			t.Errorf("expected error for interior wildcard %q", p)
		}
	}
}

func TestReadMetrics_AllZeroOnFreshLoad(t *testing.T) {
	l := requireRootBPF(t)
	snap, err := l.ReadMetrics()
	if err != nil {
		t.Fatalf("ReadMetrics: %v", err)
	}
	for id, v := range snap {
		if v != 0 {
			t.Errorf("metric[%d] = %d, want 0 on fresh load", id, v)
		}
	}
}

func TestUnpin(t *testing.T) {
	l := requireRootBPF(t)
	pinDir := l.PinDir()
	cfg := Config{
		CorednsIP:      net.ParseIP("10.100.0.10"),
		HostResolverIP: net.ParseIP("10.0.0.2"),
	}
	if err := l.PopulateConfig(cfg); err != nil {
		t.Fatalf("PopulateConfig: %v", err)
	}
	// Confirm pinned files exist under pinDir.
	entries, err := os.ReadDir(pinDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("expected pinned maps under %s, got err=%v entries=%d", pinDir, err, len(entries))
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := l.Unpin(); err != nil {
		t.Fatalf("Unpin: %v", err)
	}
	if _, err := os.Stat(pinDir); !os.IsNotExist(err) {
		t.Fatalf("pin dir still exists after Unpin: err=%v", err)
	}
}

// Sanity check: lookup of a nonexistent suffix key returns ErrKeyNotExist
// — confirms the map type behaves as we expect for hash lookups.
func TestSuffixRules_LookupMiss(t *testing.T) {
	l := requireRootBPF(t)
	var key DnsGatewaySuffixKey
	var val DnsGatewaySuffixValue
	err := l.objs.SuffixRules.Lookup(key, &val)
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("expected ErrKeyNotExist, got %v", err)
	}
}
