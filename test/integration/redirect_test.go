//go:build linux

package integration

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	bpf "github.com/viveksb007/bpf-dns-gateway/internal/ebpf"
)

const (
	corednsIP = "10.100.0.10"
	hostIP    = "169.254.169.253"
	podIP     = "10.0.5.23"
	podPort   = 0xa9c9 // 43465 in network bytes
	txid      = 0x8a3f
)

func loadGateway(t *testing.T) *bpf.Loader {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root to load eBPF programs")
	}
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		t.Skipf("bpffs not mounted: %v", err)
	}
	pinDir := filepath.Join("/sys/fs/bpf", "dns-gateway-itest-"+t.Name())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	l, err := bpf.New(pinDir)
	if err != nil {
		t.Fatalf("Loader.New: %v", err)
	}
	t.Cleanup(func() {
		_ = l.Close()
		_ = l.Unpin()
	})
	if err := l.PopulateConfig(bpf.Config{
		CorednsIP:      net.ParseIP(corednsIP),
		HostResolverIP: net.ParseIP(hostIP),
	}); err != nil {
		t.Fatalf("PopulateConfig: %v", err)
	}
	return l
}

// buildDNSQuery crafts a complete ETH+IPv4+UDP+DNS query packet from
// pod -> CoreDNS for the given QNAME.
func buildDNSQuery(t *testing.T, qname string) []byte {
	t.Helper()
	dst := net.ParseIP(corednsIP).To4()
	src := net.ParseIP(podIP).To4()

	// ETH (dst, src, type=IPv4)
	eth := make([]byte, 14)
	copy(eth[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(eth[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)

	// DNS payload
	dns := buildDNSWire(qname, false /* response */)
	udpLen := 8 + len(dns)
	totalIPLen := 20 + udpLen

	// IP
	ip := make([]byte, 20)
	ip[0] = 0x45 // ihl=5, version=4
	ip[1] = 0
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalIPLen))
	binary.BigEndian.PutUint16(ip[4:6], 0xabcd) // id
	binary.BigEndian.PutUint16(ip[6:8], 0)      // flags+frag
	ip[8] = 64                                  // ttl
	ip[9] = 17                                  // protocol UDP
	binary.BigEndian.PutUint16(ip[10:12], 0)    // checksum (filled below)
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	csum := ipChecksum(ip)
	binary.BigEndian.PutUint16(ip[10:12], csum)

	// UDP
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], podPort)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udp[6:8], 0) // checksum 0 (legal for UDPv4 query)

	pkt := append(eth, ip...)
	pkt = append(pkt, udp...)
	pkt = append(pkt, dns...)
	return pkt
}

// buildDNSResponse crafts ETH+IPv4+UDP+DNS response from VPC resolver to
// pod (for the SNAT path).
func buildDNSResponse(t *testing.T, qname string) []byte {
	t.Helper()
	src := net.ParseIP(hostIP).To4()
	dst := net.ParseIP(podIP).To4()

	eth := make([]byte, 14)
	copy(eth[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(eth[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)

	dns := buildDNSWire(qname, true /* response */)
	udpLen := 8 + len(dns)
	totalIPLen := 20 + udpLen

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalIPLen))
	binary.BigEndian.PutUint16(ip[4:6], 0xdcba)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 53)
	binary.BigEndian.PutUint16(udp[2:4], podPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udp[6:8], 0)

	pkt := append(eth, ip...)
	pkt = append(pkt, udp...)
	pkt = append(pkt, dns...)
	return pkt
}

func buildDNSWire(qname string, response bool) []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], txid)
	flags := uint16(0x0100) // standard query, RD=1
	if response {
		flags = 0x8180 // response, RA=1
	}
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT
	if response {
		binary.BigEndian.PutUint16(hdr[6:8], 1) // ANCOUNT (we'll skip answer body for SNAT test)
	}
	q := encodeQName(qname)
	q = append(q, 0, 1, 0, 1) // QTYPE A, QCLASS IN
	out := append(hdr, q...)
	if response {
		// Append a tiny dummy answer record so the kernel sees a valid
		// DNS payload. Pointer 0xc00c -> name at offset 12.
		ans := []byte{
			0xc0, 0x0c, // name pointer to QNAME
			0, 1, // type A
			0, 1, // class IN
			0, 0, 0, 60, // TTL
			0, 4, // RDLENGTH
			192, 0, 2, 1, // RDATA: 192.0.2.1
		}
		out = append(out, ans...)
	}
	return out
}

func encodeQName(name string) []byte {
	var out []byte
	if name == "" {
		return []byte{0}
	}
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			out = append(out, byte(i-start))
			out = append(out, []byte(name[start:i])...)
			start = i + 1
		}
	}
	if start < len(name) {
		out = append(out, byte(len(name)-start))
		out = append(out, []byte(name[start:])...)
	}
	out = append(out, 0)
	return out
}

func ipChecksum(hdr []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func runIngress(t *testing.T, l *bpf.Loader, pkt []byte) (ret uint32, out []byte) {
	t.Helper()
	out = make([]byte, len(pkt))
	r, err := l.IngressProgram().Run(&ebpf.RunOptions{
		Data:    pkt,
		DataOut: out,
	})
	if err != nil {
		t.Fatalf("ingress Run: %v", err)
	}
	return r, out
}

func runEgress(t *testing.T, l *bpf.Loader, pkt []byte) (ret uint32, out []byte) {
	t.Helper()
	out = make([]byte, len(pkt))
	r, err := l.EgressProgram().Run(&ebpf.RunOptions{
		Data:    pkt,
		DataOut: out,
	})
	if err != nil {
		t.Fatalf("egress Run: %v", err)
	}
	return r, out
}

func TestDNATMatchingSuffix(t *testing.T) {
	l := loadGateway(t)
	if err := l.PopulateSuffixRules([]string{"*.s3.amazonaws.com"}); err != nil {
		t.Fatalf("PopulateSuffixRules: %v", err)
	}

	pkt := buildDNSQuery(t, "mybucket.s3.amazonaws.com")
	ret, out := runIngress(t, l, pkt)
	if ret != 0 {
		t.Errorf("ingress ret = %d, want TC_ACT_OK (0)", ret)
	}
	gotDst := net.IP(out[14+16 : 14+20])
	wantDst := net.ParseIP(hostIP).To4()
	if !gotDst.Equal(wantDst) {
		t.Errorf("dst IP = %s, want %s", gotDst, wantDst)
	}
	// IP src must be unchanged.
	gotSrc := net.IP(out[14+12 : 14+16])
	if !gotSrc.Equal(net.ParseIP(podIP).To4()) {
		t.Errorf("src IP changed: %s, want %s", gotSrc, podIP)
	}

	// Conntrack entry must exist.
	if !conntrackExists(t, l) {
		t.Error("conntrack entry missing after DNAT")
	}
}

func TestPassthroughNoMatch(t *testing.T) {
	l := loadGateway(t)
	if err := l.PopulateSuffixRules([]string{"*.s3.amazonaws.com"}); err != nil {
		t.Fatalf("PopulateSuffixRules: %v", err)
	}

	pkt := buildDNSQuery(t, "kubernetes.default.svc.cluster.local")
	ret, out := runIngress(t, l, pkt)
	if ret != 0 {
		t.Errorf("ingress ret = %d, want TC_ACT_OK (0)", ret)
	}
	// Bytes must be unchanged (no DNAT).
	if !bytes.Equal(pkt, out) {
		t.Errorf("non-matching query was modified")
	}
	if conntrackExists(t, l) {
		t.Error("conntrack entry created for non-matching query")
	}
}

func TestPassthroughBypass(t *testing.T) {
	l := loadGateway(t)
	if err := l.PopulateSuffixRules([]string{"*.s3.amazonaws.com"}); err != nil {
		t.Fatalf("PopulateSuffixRules: %v", err)
	}
	if err := l.SetBypass(true); err != nil {
		t.Fatalf("SetBypass: %v", err)
	}
	pkt := buildDNSQuery(t, "mybucket.s3.amazonaws.com")
	_, out := runIngress(t, l, pkt)
	if !bytes.Equal(pkt, out) {
		t.Errorf("matching query was DNAT'd while bypass=1")
	}
}

func TestSNATResponse(t *testing.T) {
	l := loadGateway(t)
	if err := l.PopulateSuffixRules([]string{"*.s3.amazonaws.com"}); err != nil {
		t.Fatalf("PopulateSuffixRules: %v", err)
	}

	// Step 1: send query so conntrack gets populated.
	pkt := buildDNSQuery(t, "mybucket.s3.amazonaws.com")
	if _, _ = runIngress(t, l, pkt); !conntrackExists(t, l) {
		t.Fatalf("conntrack not populated by ingress")
	}

	// Step 2: send crafted response from VPC DNS to pod.
	resp := buildDNSResponse(t, "mybucket.s3.amazonaws.com")
	ret, out := runEgress(t, l, resp)
	if ret != 0 {
		t.Errorf("egress ret = %d, want TC_ACT_OK (0)", ret)
	}
	gotSrc := net.IP(out[14+12 : 14+16])
	wantSrc := net.ParseIP(corednsIP).To4()
	if !gotSrc.Equal(wantSrc) {
		t.Errorf("egress src IP = %s, want %s (CoreDNS)", gotSrc, wantSrc)
	}
	// Egress should delete the conntrack entry on success.
	if conntrackExists(t, l) {
		t.Error("conntrack entry still present after successful SNAT")
	}
}

func TestSNATBypassesUnknownTxid(t *testing.T) {
	l := loadGateway(t)
	if err := l.PopulateSuffixRules([]string{"*.s3.amazonaws.com"}); err != nil {
		t.Fatalf("PopulateSuffixRules: %v", err)
	}
	// Send response with no prior ingress -> no conntrack -> passthrough.
	resp := buildDNSResponse(t, "mybucket.s3.amazonaws.com")
	_, out := runEgress(t, l, resp)
	if !bytes.Equal(resp, out) {
		t.Error("egress modified packet despite missing conntrack entry")
	}
}

// conntrackExists returns true iff conntrack_map has any entries.
// openConntrack opens the pinned conntrack_map for direct inspection.
func openConntrack(t *testing.T, l *bpf.Loader) *ebpf.Map {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(filepath.Join(l.PinDir(), "conntrack_map"), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap conntrack_map: %v", err)
	}
	return m
}

func conntrackExists(t *testing.T, l *bpf.Loader) bool {
	t.Helper()
	m := openConntrack(t, l)
	defer m.Close()
	iter := m.Iterate()
	var k bpf.DnsGatewayConntrackKey
	var v bpf.DnsGatewayConntrackValue
	return iter.Next(&k, &v)
}
