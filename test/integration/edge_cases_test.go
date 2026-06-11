//go:build linux

package integration

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	bpf "github.com/viveksb007/bpf-dns-gateway/internal/ebpf"
)

// buildQueryProto wraps an arbitrary L4 payload (UDP or TCP) into a full
// ETH+IPv4 packet from pod -> CoreDNS. proto is IPPROTO_UDP (17) or
// IPPROTO_TCP (6). udpCsum lets a test force a zero UDP checksum.
func buildQueryProto(proto byte, dnsPayload []byte, udpCsumZero bool) []byte {
	dst := net.ParseIP(corednsIP).To4()
	src := net.ParseIP(podIP).To4()

	eth := make([]byte, 14)
	copy(eth[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(eth[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)

	var l4 []byte
	if proto == 17 { // UDP
		l4 = make([]byte, 8)
		binary.BigEndian.PutUint16(l4[0:2], podPort)
		binary.BigEndian.PutUint16(l4[2:4], 53)
		binary.BigEndian.PutUint16(l4[4:6], uint16(8+len(dnsPayload)))
		if !udpCsumZero {
			binary.BigEndian.PutUint16(l4[6:8], 0x1234) // arbitrary nonzero; eBPF doesn't verify
		}
		l4 = append(l4, dnsPayload...)
	} else { // TCP (minimal 20-byte header; DNS-over-TCP has a 2-byte length prefix but we never parse it)
		l4 = make([]byte, 20)
		binary.BigEndian.PutUint16(l4[0:2], podPort)
		binary.BigEndian.PutUint16(l4[2:4], 53)
		l4[12] = 0x50 // data offset = 5 words
		l4 = append(l4, dnsPayload...)
	}

	totalIPLen := 20 + len(l4)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalIPLen))
	binary.BigEndian.PutUint16(ip[4:6], 0xabcd)
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	pkt := append(eth, ip...)
	pkt = append(pkt, l4...)
	return pkt
}

// dnsHeader builds a 12-byte DNS query header with the given qdcount.
func dnsHeader(qdcount uint16) []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[0:2], txid)
	binary.BigEndian.PutUint16(h[2:4], 0x0100) // query, RD
	binary.BigEndian.PutUint16(h[4:6], qdcount)
	return h
}

// question encodes a QNAME + QTYPE A + QCLASS IN.
func question(qname string) []byte {
	q := encodeQName(qname)
	return append(q, 0, 1, 0, 1)
}

// metricDelta runs fn and returns the change in the given metric.
func metricDelta(t *testing.T, l *bpf.Loader, id bpf.MetricID, fn func()) uint64 {
	t.Helper()
	before, err := l.ReadMetrics()
	if err != nil {
		t.Fatalf("ReadMetrics before: %v", err)
	}
	fn()
	after, err := l.ReadMetrics()
	if err != nil {
		t.Fatalf("ReadMetrics after: %v", err)
	}
	return after[id] - before[id]
}

func edgeLoader(t *testing.T) *bpf.Loader {
	t.Helper()
	l := loadGateway(t)
	if err := l.PopulateSuffixRules([]string{"*.s3.amazonaws.com"}); err != nil {
		t.Fatalf("PopulateSuffixRules: %v", err)
	}
	return l
}

// expectPassthrough runs ingress and asserts the packet is unmodified
// and no conntrack entry was created.
func expectPassthrough(t *testing.T, l *bpf.Loader, pkt []byte, what string) {
	t.Helper()
	ret, out := runIngress(t, l, pkt)
	if ret != 0 {
		t.Errorf("%s: ret = %d, want TC_ACT_OK", what, ret)
	}
	if !bytes.Equal(pkt, out) {
		t.Errorf("%s: packet was modified (expected passthrough)", what)
	}
	if conntrackExists(t, l) {
		t.Errorf("%s: conntrack entry created (expected none)", what)
	}
}

func TestEdge_CompressionPointer(t *testing.T) {
	l := edgeLoader(t)
	// QNAME starting with a compression pointer (0xC0) -> parse_error,
	// passthrough.
	dns := dnsHeader(1)
	dns = append(dns, 0xC0, 0x0C) // pointer
	dns = append(dns, 0, 1, 0, 1) // qtype/qclass
	pkt := buildQueryProto(17, dns, false)

	delta := metricDelta(t, l, bpf.MetricParseError, func() {
		expectPassthrough(t, l, pkt, "compression pointer")
	})
	if delta == 0 {
		t.Error("parse_error metric not incremented for compression pointer")
	}
}

func TestEdge_QDCountZero(t *testing.T) {
	l := edgeLoader(t)
	dns := dnsHeader(0)
	pkt := buildQueryProto(17, dns, false)
	expectPassthrough(t, l, pkt, "QDCOUNT=0")
}

func TestEdge_QDCountTwo(t *testing.T) {
	l := edgeLoader(t)
	// QDCOUNT=2 with a matching first question must still passthrough
	// (parse_error), because intent is ambiguous.
	dns := dnsHeader(2)
	dns = append(dns, question("mybucket.s3.amazonaws.com")...)
	dns = append(dns, question("other.example.com")...)
	pkt := buildQueryProto(17, dns, false)

	delta := metricDelta(t, l, bpf.MetricParseError, func() {
		expectPassthrough(t, l, pkt, "QDCOUNT=2")
	})
	if delta == 0 {
		t.Error("parse_error not incremented for QDCOUNT>1")
	}
}

func TestEdge_LabelLenTooLong(t *testing.T) {
	l := edgeLoader(t)
	// A label-length byte > 63 (but < 0xC0) is invalid -> parse_error,
	// passthrough.
	dns := dnsHeader(1)
	dns = append(dns, 0x40) // 64 — illegal label length
	dns = append(dns, bytes.Repeat([]byte{'a'}, 64)...)
	dns = append(dns, 0, 0, 1, 0, 1)
	pkt := buildQueryProto(17, dns, false)

	delta := metricDelta(t, l, bpf.MetricParseError, func() {
		expectPassthrough(t, l, pkt, "label_len>63")
	})
	if delta == 0 {
		t.Error("parse_error not incremented for oversized label length")
	}
}

func TestEdge_TCPOnPort53(t *testing.T) {
	l := edgeLoader(t)
	// TCP DNS: protocol != UDP -> ignored entirely, passthrough.
	dns := dnsHeader(1)
	dns = append(dns, question("mybucket.s3.amazonaws.com")...)
	pkt := buildQueryProto(6, dns, false) // IPPROTO_TCP
	expectPassthrough(t, l, pkt, "TCP on port 53")
}

func TestEdge_UDPChecksumZero(t *testing.T) {
	l := edgeLoader(t)
	// UDP checksum 0 is legal for IPv4. A matching query must still be
	// DNAT'd (BPF_F_MARK_MANGLED_0 keeps it 0 after rewrite).
	dns := dnsHeader(1)
	dns = append(dns, question("mybucket.s3.amazonaws.com")...)
	pkt := buildQueryProto(17, dns, true /* udpCsumZero */)

	ret, out := runIngress(t, l, pkt)
	if ret != 0 {
		t.Errorf("ret = %d, want TC_ACT_OK", ret)
	}
	gotDst := net.IP(out[14+16 : 14+20])
	if !gotDst.Equal(net.ParseIP(hostIP).To4()) {
		t.Errorf("csum=0 matching query not DNAT'd: dst=%s", gotDst)
	}
	// UDP checksum must remain 0.
	udpCsum := binary.BigEndian.Uint16(out[14+20+6 : 14+20+8])
	if udpCsum != 0 {
		t.Errorf("UDP checksum became %#x, want 0 (BPF_F_MARK_MANGLED_0)", udpCsum)
	}
}

func TestEdge_QNAMEOver128(t *testing.T) {
	l := edgeLoader(t)
	// Build a name whose wire length exceeds MAX_DNS_NAME_LEN (128).
	// Several 60-char labels under .s3.amazonaws.com.
	long := ""
	for i := 0; i < 3; i++ {
		long += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
	}
	long += "s3.amazonaws.com"
	dns := dnsHeader(1)
	dns = append(dns, question(long)...)
	pkt := buildQueryProto(17, dns, false)
	// Over-length QNAME -> passthrough (no DNAT). It may or may not bump
	// parse_error depending on where the bound trips; we only require
	// passthrough + no conntrack.
	expectPassthrough(t, l, pkt, "QNAME>128 bytes")
}

func TestEdge_ManyShortLabels(t *testing.T) {
	l := edgeLoader(t)
	// > MAX_LABELS (20) single-char labels -> passthrough.
	name := ""
	for i := 0; i < 25; i++ {
		name += "a."
	}
	name += "s3.amazonaws.com"
	dns := dnsHeader(1)
	dns = append(dns, question(name)...)
	pkt := buildQueryProto(17, dns, false)
	expectPassthrough(t, l, pkt, ">20 labels")
}

func TestEdge_UppercasePassthrough(t *testing.T) {
	l := edgeLoader(t)
	// MVP limitation: no BPF-side lowercasing. An uppercase QNAME does
	// NOT match the lowercase rule and must passthrough to CoreDNS
	// (design.md §9.1).
	dns := dnsHeader(1)
	dns = append(dns, question("MyBucket.S3.AmazonAWS.CoM")...)
	pkt := buildQueryProto(17, dns, false)
	expectPassthrough(t, l, pkt, "uppercase QNAME")
}

func TestEdge_ConcurrentAandAAAA(t *testing.T) {
	l := edgeLoader(t)
	// Two queries from the same pod source port with DIFFERENT txids
	// (as a resolver firing A + AAAA in parallel does). Both must be
	// DNAT'd and both responses must SNAT independently — the txid in
	// the conntrack key prevents collision.
	const (
		txidA    = 0x1111
		txidAAAA = 0x2222
	)
	runIngress(t, l, queryWithTxid(txidA, 1))     // type A
	runIngress(t, l, queryWithTxid(txidAAAA, 28)) // type AAAA

	// Two distinct conntrack entries should exist.
	if n := conntrackCount(t, l); n != 2 {
		t.Fatalf("conntrack entries = %d, want 2 (A + AAAA distinct txids)", n)
	}

	// Both responses SNAT independently.
	for _, tx := range []uint16{txidA, txidAAAA} {
		ret, out := runEgress(t, l, responseWithTxid(tx))
		if ret != 0 {
			t.Errorf("txid %#x: egress ret %d", tx, ret)
		}
		gotSrc := net.IP(out[14+12 : 14+16])
		if !gotSrc.Equal(net.ParseIP(corednsIP).To4()) {
			t.Errorf("txid %#x: response not SNAT'd, src=%s", tx, gotSrc)
		}
	}
	if conntrackExists(t, l) {
		t.Error("conntrack entries remain after both responses SNAT'd")
	}
}

// queryWithTxid builds a matching UDP DNS query with a specific txid +
// qtype.
func queryWithTxid(tx uint16, qtype uint16) []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[0:2], tx)
	binary.BigEndian.PutUint16(h[2:4], 0x0100)
	binary.BigEndian.PutUint16(h[4:6], 1)
	q := encodeQName("mybucket.s3.amazonaws.com")
	q = append(q, byte(qtype>>8), byte(qtype), 0, 1)
	return buildQueryProto(17, append(h, q...), false)
}

// responseWithTxid builds a VPC-DNS response with a specific txid.
func responseWithTxid(tx uint16) []byte {
	src := net.ParseIP(hostIP).To4()
	dst := net.ParseIP(podIP).To4()

	eth := make([]byte, 14)
	copy(eth[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(eth[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)

	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[0:2], tx)
	binary.BigEndian.PutUint16(h[2:4], 0x8180)
	binary.BigEndian.PutUint16(h[4:6], 1)
	binary.BigEndian.PutUint16(h[6:8], 1)
	dns := append(h, question("mybucket.s3.amazonaws.com")...)

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 53)
	binary.BigEndian.PutUint16(udp[2:4], podPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(dns)))
	udp = append(udp, dns...)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(udp)))
	binary.BigEndian.PutUint16(ip[4:6], 0xdcba)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	pkt := append(eth, ip...)
	pkt = append(pkt, udp...)
	return pkt
}

// conntrackCount returns the number of conntrack entries.
func conntrackCount(t *testing.T, l *bpf.Loader) int {
	t.Helper()
	m := openConntrack(t, l)
	defer m.Close()
	iter := m.Iterate()
	var k bpf.DnsGatewayConntrackKey
	var v bpf.DnsGatewayConntrackValue
	n := 0
	for iter.Next(&k, &v) {
		n++
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate conntrack: %v", err)
	}
	return n
}
