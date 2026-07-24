package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/viveksb007/bpf-dns-gateway/internal/dnsenc"
)

// Action mirrors the ACTION_* constants in bpf/dns_gateway.h.
type Action uint32

const (
	// ActionHostResolve redirects matching queries to the VPC resolver.
	ActionHostResolve Action = 1
	// ActionClusterResolve keeps matching queries on CoreDNS.
	ActionClusterResolve Action = 2
)

// The eBPF C compares config_map fields against packet fields like
// iph.daddr and udp.dest, which the kernel exposes in network byte order
// without conversion. Cilium ebpf serializes Go struct fields to the map
// in host byte order, so we must assign each uint16/uint32 field the
// host integer whose in-memory bytes already match the wire bytes. This
// is what binary.NativeEndian does when given the wire bytes directly.

// dnsPort53 is 0x0035 in network bytes; encode as the host uint16 whose
// memory representation matches that pattern.
var dnsPort53 = nativeUint16([]byte{0x00, 0x35})

// Config carries the values written to the single-entry config_map.
//
// CorednsIP and HostResolverIP must be IPv4. Bypass=true sets the bypass
// flag; the eBPF programs check it on every packet. DefaultAction is the
// action for queries matching no suffix rule; the zero value is treated
// as ActionClusterResolve (the pre-defaultAction behavior).
type Config struct {
	CorednsIP      net.IP
	HostResolverIP net.IP
	Bypass         bool
	DefaultAction  Action
}

// PopulateConfig writes the full config entry to config_map[0]. It is safe
// to call repeatedly to update any field; the entire structure is
// rewritten atomically by the BPF map.
func (l *Loader) PopulateConfig(cfg Config) error {
	c4 := cfg.CorednsIP.To4()
	if c4 == nil {
		return fmt.Errorf("corednsIP %s is not IPv4", cfg.CorednsIP)
	}
	h4 := cfg.HostResolverIP.To4()
	if h4 == nil {
		return fmt.Errorf("hostResolverIP %s is not IPv4", cfg.HostResolverIP)
	}

	bypass := uint16(0)
	if cfg.Bypass {
		bypass = 1
	}
	defaultAction := cfg.DefaultAction
	if defaultAction == 0 {
		defaultAction = ActionClusterResolve
	}
	if defaultAction != ActionHostResolve && defaultAction != ActionClusterResolve {
		return fmt.Errorf("invalid DefaultAction %d", defaultAction)
	}

	val := DnsGatewayGatewayConfig{
		CorednsIp:      nativeUint32IP(c4),
		HostResolverIp: nativeUint32IP(h4),
		DnsPort:        dnsPort53,
		Bypass:         bypass,
		DefaultAction:  uint32(defaultAction),
	}
	var key uint32 = 0
	l.configMu.Lock()
	defer l.configMu.Unlock()
	if err := l.objs.ConfigMap.Update(key, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update config_map: %w", err)
	}
	return nil
}

// SetBypass toggles the bypass flag in config_map[0] without modifying
// the other fields. The read-modify-write is serialized by configMu:
// the health checker and the shutdown path may both call SetBypass
// concurrently, and an unserialized interleaving could lose the
// shutdown's bypass=1 write.
func (l *Loader) SetBypass(on bool) error {
	l.configMu.Lock()
	defer l.configMu.Unlock()
	var key uint32 = 0
	var val DnsGatewayGatewayConfig
	if err := l.objs.ConfigMap.Lookup(key, &val); err != nil {
		return fmt.Errorf("lookup config_map: %w", err)
	}
	if on {
		val.Bypass = 1
	} else {
		val.Bypass = 0
	}
	if err := l.objs.ConfigMap.Update(key, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update config_map: %w", err)
	}
	return nil
}

// SuffixRule pairs a wildcard pattern with its action for the BPF map.
type SuffixRule struct {
	Pattern string
	Action  Action
}

// PopulateSuffixRules reconciles suffix_rules with the given rules.
//
// Each pattern must be of the form "*.suffix" (wildcard-only in MVP).
// Exact patterns and interior wildcards are rejected. The map is fully
// reconciled: keys present in the map but not in rules are deleted;
// keys missing are added; keys whose action changed are updated in
// place.
func (l *Loader) PopulateSuffixRules(rules []SuffixRule) error {
	desired := make(map[DnsGatewaySuffixKey]Action, len(rules))
	for _, r := range rules {
		if r.Action != ActionHostResolve && r.Action != ActionClusterResolve {
			return fmt.Errorf("pattern %q has invalid action %d", r.Pattern, r.Action)
		}
		suffix, isWildcard := dnsenc.ParsePattern(r.Pattern)
		if !isWildcard {
			return fmt.Errorf("pattern %q must use *.suffix form (exact match unsupported in MVP)", r.Pattern)
		}
		// Reject interior wildcards (e.g. "*.*.amazonaws.com" or
		// "*.s3.*.amazonaws.com"). The BPF matcher does byte-for-byte
		// suffix comparison and would otherwise install a literal '*'
		// byte that never matches a real DNS query.
		if strings.Contains(suffix, "*") {
			return fmt.Errorf("pattern %q has interior wildcard; only leading *.suffix is supported", r.Pattern)
		}
		key, err := dnsenc.EncodeSuffix(suffix)
		if err != nil {
			return fmt.Errorf("encode pattern %q: %w", r.Pattern, err)
		}
		mapKey := DnsGatewaySuffixKey{Name: key}
		if prev, dup := desired[mapKey]; dup && prev != r.Action {
			return fmt.Errorf("pattern %q appears with conflicting actions", r.Pattern)
		}
		desired[mapKey] = r.Action
	}

	// Snapshot existing keys + actions so we can compute the diff.
	existing := make(map[DnsGatewaySuffixKey]Action)
	iter := l.objs.SuffixRules.Iterate()
	var k DnsGatewaySuffixKey
	var v DnsGatewaySuffixValue
	for iter.Next(&k, &v) {
		existing[k] = Action(v.Action)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate suffix_rules: %w", err)
	}

	// Delete stale keys FIRST so a near-full map can free capacity
	// before we try to add replacements. Otherwise a reconcile that
	// swaps any rule at the 1024-entry map capacity would fail with
	// ENOSPC on the first Update and leave the old rules in place.
	for key := range existing {
		if _, ok := desired[key]; ok {
			continue
		}
		if err := l.objs.SuffixRules.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale suffix rule: %w", err)
		}
	}
	// Add new keys and update keys whose action changed.
	for key, action := range desired {
		if prev, ok := existing[key]; ok && prev == action {
			continue
		}
		val := DnsGatewaySuffixValue{Action: uint32(action)}
		if err := l.objs.SuffixRules.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("add suffix rule: %w", err)
		}
	}
	return nil
}

// CountSuffixRules returns the current number of entries in suffix_rules.
// O(n) — iterates the map.
func (l *Loader) CountSuffixRules() (int, error) {
	iter := l.objs.SuffixRules.Iterate()
	var k DnsGatewaySuffixKey
	var v DnsGatewaySuffixValue
	count := 0
	for iter.Next(&k, &v) {
		count++
	}
	if err := iter.Err(); err != nil {
		return 0, fmt.Errorf("iterate suffix_rules: %w", err)
	}
	return count, nil
}

// MetricID enumerates the metric_id values in bpf/dns_gateway.h.
type MetricID uint32

const (
	MetricTotalPackets MetricID = iota
	MetricDNSQueries
	MetricSuffixMatch
	MetricSuffixNoMatch
	MetricBypassActive
	MetricParseError
	MetricEgressSnat
	MetricEgressConntrackMiss
	MetricEgressTotal
	// MetricNatError counts NAT rewrite helper failures where the
	// packet was cleanly reverted and passed through unmodified.
	MetricNatError
	// MetricNatRevertFail counts NAT failures where the revert itself
	// also failed (packet possibly inconsistent). Should stay 0.
	MetricNatRevertFail
	// MetricRedirected counts queries whose resolved action was
	// host-resolve and whose DNAT fully succeeded (rule or default).
	MetricRedirected
	// MetricClusterResolved counts queries deliberately kept on
	// CoreDNS by a cluster-resolve action (rule or default).
	MetricClusterResolved
	metricMax
)

// MetricSnapshot is a sum across CPUs for each metric ID.
type MetricSnapshot [metricMax]uint64

// ReadMetrics reads the per-CPU metrics_map and sums each metric across
// all online CPUs.
func (l *Loader) ReadMetrics() (MetricSnapshot, error) {
	var snap MetricSnapshot
	for id := range int(metricMax) {
		var perCPU []uint64
		if err := l.objs.MetricsMap.Lookup(uint32(id), &perCPU); err != nil {
			return snap, fmt.Errorf("lookup metric %d: %w", id, err)
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		snap[id] = sum
	}
	return snap, nil
}

// nativeUint16 reinterprets two bytes (network/wire order) as a host
// uint16 whose in-memory representation matches the given bytes.
func nativeUint16(b []byte) uint16 {
	return binary.NativeEndian.Uint16(b)
}

// nativeUint32IP returns the uint32 whose in-memory bytes match the
// given 4-byte IPv4 address (already in network order).
func nativeUint32IP(ip4 net.IP) uint32 {
	return binary.NativeEndian.Uint32(ip4)
}
