//go:build linux

package ebpf

import (
	"os"
	"sync/atomic"
	"testing"

	"github.com/vishvananda/netlink"
)

var vethCounter atomic.Uint64

// createTestVeth makes a fresh veth pair and returns the host-side
// ifindex. Each call gets a unique name even within the same test.
func createTestVeth(t *testing.T) int {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root for veth + TCX attach")
	}
	// Linux veth names must be <= 15 bytes. uniqueSuffix(8) + index(4)
	// = 12, plus 3-byte prefix.
	suf := uniqueSuffix(t)[:4] + indexSuffix()
	hostName := "va-" + suf
	peerName := "vb-" + suf
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: hostName},
		PeerName:  peerName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("LinkAdd: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	link, err := netlink.LinkByName(hostName)
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	return link.Attrs().Index
}

func indexSuffix() string {
	n := vethCounter.Add(1)
	const hex = "0123456789abcdef"
	out := make([]byte, 4)
	for i := 0; i < 4; i++ {
		out[i] = hex[(n>>(uint(i)*4))&0xF]
	}
	return string(out)
}

func uniqueSuffix(t *testing.T) string {
	// Test name uniqueness + pid is enough for concurrent runs.
	pid := os.Getpid()
	return shortHash(t.Name() + string(rune(pid)))
}

func shortHash(s string) string {
	// Trivial 8-byte hex of FNV; avoids importing crypto for tests.
	h := uint64(1469598103934665603)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = hex[(h>>(uint(i)*4))&0xF]
	}
	return string(out)
}

func TestAttachManager_AttachDetach(t *testing.T) {
	l := requireRootBPF(t)
	mgr := NewAttachManager(l)

	ifindex := createTestVeth(t)

	if err := mgr.Attach(ifindex); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if !mgr.IsAttached(ifindex) {
		t.Errorf("IsAttached(%d) = false after Attach", ifindex)
	}
	if got := mgr.AttachedCount(); got != 1 {
		t.Errorf("AttachedCount = %d, want 1", got)
	}

	// Idempotent re-attach.
	if err := mgr.Attach(ifindex); err != nil {
		t.Fatalf("Attach (second call): %v", err)
	}
	if got := mgr.AttachedCount(); got != 1 {
		t.Errorf("AttachedCount after duplicate Attach = %d, want 1", got)
	}

	if err := mgr.Detach(ifindex); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if mgr.IsAttached(ifindex) {
		t.Errorf("IsAttached(%d) = true after Detach", ifindex)
	}
	// Idempotent detach.
	if err := mgr.Detach(ifindex); err != nil {
		t.Fatalf("Detach (second call): %v", err)
	}
}

func TestAttachManager_DetachAll(t *testing.T) {
	l := requireRootBPF(t)
	mgr := NewAttachManager(l)

	idxs := []int{createTestVeth(t), createTestVeth(t)}
	for _, idx := range idxs {
		if err := mgr.Attach(idx); err != nil {
			t.Fatalf("Attach(%d): %v", idx, err)
		}
	}
	if got := mgr.AttachedCount(); got != len(idxs) {
		t.Errorf("AttachedCount = %d, want %d", got, len(idxs))
	}
	if err := mgr.DetachAll(); err != nil {
		t.Fatalf("DetachAll: %v", err)
	}
	if got := mgr.AttachedCount(); got != 0 {
		t.Errorf("AttachedCount after DetachAll = %d, want 0", got)
	}
}

func TestAttachManager_RejectInvalidIfindex(t *testing.T) {
	l := requireRootBPF(t)
	mgr := NewAttachManager(l)
	for _, bad := range []int{0, -1} {
		if err := mgr.Attach(bad); err == nil {
			t.Errorf("Attach(%d): expected error", bad)
		}
	}
}
