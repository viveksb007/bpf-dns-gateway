//go:build linux

package controller

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	bpf "github.com/viveksb007/bpf-dns-gateway/internal/ebpf"
	"github.com/viveksb007/bpf-dns-gateway/internal/netlinkmon"
)

var vethCounter atomic.Uint64

func uniqVethName(prefix string) string {
	n := vethCounter.Add(1)
	const hex = "0123456789abcdef"
	out := make([]byte, 4)
	for i := range 4 {
		out[i] = hex[(n>>(uint(i)*4))&0xF]
	}
	return prefix + string(out)
}

func newTestController(t *testing.T) *Controller {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root for eBPF + netlink + veth")
	}
	pinDir := filepath.Join("/sys/fs/bpf", "dns-gateway-ctrl-"+uniqVethName(""))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	loader, err := bpf.New(pinDir)
	if err != nil {
		t.Fatalf("bpf.New: %v", err)
	}
	t.Cleanup(func() {
		_ = loader.Close()
		_ = loader.Unpin()
	})
	if err := loader.PopulateConfig(bpf.Config{
		CorednsIP:      net.ParseIP("10.100.0.10"),
		HostResolverIP: net.ParseIP("10.0.0.2"),
	}); err != nil {
		t.Fatalf("PopulateConfig: %v", err)
	}
	mgr := bpf.NewAttachManager(loader)
	mon := netlinkmon.New(nil)
	c, err := New(Options{Loader: loader, Manager: mgr, Monitor: mon})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestController_AttachOnAdd(t *testing.T) {
	c := newTestController(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = c.monitor.Start(ctx) }()
	go func() { _ = c.Run(ctx) }()

	// Wait briefly for monitor to drain initial dump.
	time.Sleep(300 * time.Millisecond)
	startCount := c.AttachedCount()

	name := uniqVethName("vc-")
	peer := uniqVethName("vc-")
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		PeerName:  peer,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("LinkAdd: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })

	// Wait for the controller to attach.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c.AttachedCount() > startCount {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if c.AttachedCount() <= startCount {
		t.Fatalf("controller did not attach within deadline (count = %d, start = %d)", c.AttachedCount(), startCount)
	}

	// Delete veth -> controller should detach.
	if err := netlink.LinkDel(veth); err != nil {
		t.Fatalf("LinkDel: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c.AttachedCount() == startCount {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if c.AttachedCount() != startCount {
		t.Errorf("controller did not detach after LinkDel (count = %d, want %d)", c.AttachedCount(), startCount)
	}
}

func TestController_DetachAllOnShutdown(t *testing.T) {
	c := newTestController(t)
	ctx, cancel := context.WithCancel(context.Background())

	go func() { _ = c.monitor.Start(ctx) }()
	runDone := make(chan error, 1)
	go func() { runDone <- c.Run(ctx) }()

	time.Sleep(200 * time.Millisecond)

	// Pre-existing veths on the host should already be attached.
	// At minimum we expect the EKS-managed veths in the test
	// environment, but the test does not depend on any specific
	// number; we only assert detach-all clears whatever we tracked.
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
	if c.AttachedCount() != 0 {
		t.Errorf("AttachedCount after shutdown = %d, want 0", c.AttachedCount())
	}
}

func TestController_BypassToggle(t *testing.T) {
	c := newTestController(t)
	if err := c.SetBypass(true); err != nil {
		t.Fatalf("SetBypass(true): %v", err)
	}
	if err := c.SetBypass(false); err != nil {
		t.Fatalf("SetBypass(false): %v", err)
	}
}

func TestController_NewRequiresAllOptions(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Error("expected error for empty Options")
	}
}
