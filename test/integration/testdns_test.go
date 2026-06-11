//go:build linux

package integration

import (
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// toggleDNS is a local UDP DNS responder whose health can be flipped at
// runtime: while unhealthy it drops queries (client times out -> probe
// failure); while healthy it answers. Lets a single health.Checker
// observe a fail->recover transition on one fixed IP:port — matching
// the single long-lived checker in production.
type toggleDNS struct {
	ip      net.IP
	port    int
	healthy atomic.Bool
	srv     *dns.Server
}

func startToggleDNS(t *testing.T) *toggleDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	td := &toggleDNS{
		ip:   net.ParseIP("127.0.0.1"),
		port: pc.LocalAddr().(*net.UDPAddr).Port,
	}
	td.srv = &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			if !td.healthy.Load() {
				return // drop -> client times out
			}
			m := new(dns.Msg)
			m.SetReply(r)
			if len(r.Question) == 1 && r.Question[0].Qtype == dns.TypeA {
				if rr, err := dns.NewRR(r.Question[0].Name + " 60 IN A 192.0.2.1"); err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
			_ = w.WriteMsg(m)
		}),
	}
	started := make(chan struct{})
	td.srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = td.srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = td.srv.Shutdown() })
	return td
}

func (td *toggleDNS) setHealthy(h bool) { td.healthy.Store(h) }
