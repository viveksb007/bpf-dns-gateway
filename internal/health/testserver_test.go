package health

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// newLocalPacketConn opens a UDP socket on 127.0.0.1:0 (random port).
func newLocalPacketConn(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	return pc
}

// startTestDNS spins up a UDP DNS server on a random localhost port that
// answers every A query with 192.0.2.1. Returns the address and a
// shutdown func.
func startTestDNS(t *testing.T) (addr string, shutdown func()) {
	t.Helper()

	pc := newLocalPacketConn(t)
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			if len(r.Question) == 1 && r.Question[0].Qtype == dns.TypeA {
				rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A 192.0.2.1")
				if rr != nil {
					m.Answer = append(m.Answer, rr)
				}
			}
			_ = w.WriteMsg(m)
		}),
	}

	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started

	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}
