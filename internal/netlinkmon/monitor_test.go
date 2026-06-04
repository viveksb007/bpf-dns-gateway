//go:build linux

package netlinkmon

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

var counter atomic.Uint64

func uniqName(prefix string) string {
	n := counter.Add(1)
	const hex = "0123456789abcdef"
	out := make([]byte, 4)
	for i := range 4 {
		out[i] = hex[(n>>(uint(i)*4))&0xF]
	}
	return prefix + string(out)
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root for netlink subscription + veth")
	}
}

func waitForAdd(t *testing.T, m *Monitor, name string, timeout time.Duration) Event {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case ev, ok := <-m.Events():
			if !ok {
				t.Fatal("events channel closed before expected add")
			}
			if ev.Type == EventAdd && ev.Name == name {
				return ev
			}
		case <-deadline.C:
			t.Fatalf("timeout waiting for add of %s", name)
		}
	}
}

func waitForRemove(t *testing.T, m *Monitor, name string, timeout time.Duration) Event {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case ev, ok := <-m.Events():
			if !ok {
				t.Fatal("events channel closed before expected remove")
			}
			if ev.Type == EventRemove && ev.Name == name {
				return ev
			}
		case <-deadline.C:
			t.Fatalf("timeout waiting for remove of %s", name)
		}
	}
}

func TestMonitor_AddRemoveVeth(t *testing.T) {
	requireRoot(t)
	mon := New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = mon.Start(ctx) }()

	// Drain the initial dump for a bit so existing veths don't
	// confuse the test.
	time.Sleep(200 * time.Millisecond)
	for {
		select {
		case <-mon.Events():
		default:
			goto drained
		}
	}
drained:

	name := uniqName("vt-")
	peer := uniqName("vt-")
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		PeerName:  peer,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("LinkAdd: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })

	addEv := waitForAdd(t, mon, name, 3*time.Second)
	if addEv.Ifindex <= 0 {
		t.Errorf("ifindex = %d", addEv.Ifindex)
	}

	if err := netlink.LinkDel(veth); err != nil {
		t.Fatalf("LinkDel: %v", err)
	}
	waitForRemove(t, mon, name, 3*time.Second)
}

func TestMonitor_FiltersNonVeth(t *testing.T) {
	requireRoot(t)
	mon := New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = mon.Start(ctx) }()
	time.Sleep(200 * time.Millisecond)

	// Drain initial dump.
	for {
		select {
		case <-mon.Events():
		default:
			goto drained
		}
	}
drained:

	name := uniqName("du-")
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatalf("LinkAdd dummy: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(dummy) })

	// Should NOT receive any event for the dummy interface.
	select {
	case ev := <-mon.Events():
		if ev.Name == name {
			t.Errorf("received event for non-veth %s: %+v", name, ev)
		}
	case <-time.After(500 * time.Millisecond):
		// expected: no event
	}
}

func TestMonitor_ListExistingFiresOnSubscribe(t *testing.T) {
	requireRoot(t)
	// Pre-create veth before starting the monitor.
	name := uniqName("ve-")
	peer := uniqName("ve-")
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: peer}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("LinkAdd: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })

	mon := New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = mon.Start(ctx) }()

	waitForAdd(t, mon, name, 3*time.Second)
}

func TestMonitor_CancelUnblocksFullBuffer(t *testing.T) {
	requireRoot(t)
	mon := New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- mon.Start(ctx) }()

	// Do NOT drain. Initial dump or any add will fill the buffer (32)
	// and block emit. Cancel must unblock.
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-stopped:
		if err != nil {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after ctx cancel even though buffer is full")
	}
}

func TestMonitor_ContextCancelClosesEvents(t *testing.T) {
	requireRoot(t)
	mon := New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- mon.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	cancel()
	select {
	case err := <-stopped:
		if err != nil {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}
	// Drain remaining buffered events; Events() must close eventually.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, ok := <-mon.Events()
		if !ok {
			return
		}
	}
	t.Error("Events() did not close after Start returned")
}
