package health

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeBypass records SetBypass calls.
type fakeBypass struct {
	mu    sync.Mutex
	calls []bool
	err   error
}

func (f *fakeBypass) SetBypass(on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, on)
	return nil
}

func (f *fakeBypass) lastCall() (bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return false, false
	}
	return f.calls[len(f.calls)-1], true
}

func (f *fakeBypass) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func newTestChecker(t *testing.T, threshold int, q queryFunc) (*Checker, *fakeBypass) {
	t.Helper()
	fb := &fakeBypass{}
	c, err := New(Config{
		ResolverIP:       net.ParseIP("10.0.0.2"),
		Interval:         time.Hour, // we drive probeOnce manually
		Timeout:          time.Second,
		FailureThreshold: threshold,
	}, fb, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.query = q
	return c, fb
}

func TestChecker_EnablesBypassAfterThreshold(t *testing.T) {
	failing := func(ctx context.Context, server, name string, to time.Duration) error {
		return context.DeadlineExceeded
	}
	c, fb := newTestChecker(t, 3, failing)
	ctx := context.Background()

	c.probeOnce(ctx, "10.0.0.2:53")
	c.probeOnce(ctx, "10.0.0.2:53")
	if fb.callCount() != 0 {
		t.Fatalf("bypass set before threshold reached: %v", fb.calls)
	}
	c.probeOnce(ctx, "10.0.0.2:53") // 3rd failure -> bypass on
	on, ok := fb.lastCall()
	if !ok || !on {
		t.Fatalf("expected bypass=true after threshold, calls=%v", fb.calls)
	}
	if !c.BypassActive() {
		t.Error("BypassActive() = false after enabling")
	}
	// Further failures do not re-call SetBypass.
	c.probeOnce(ctx, "10.0.0.2:53")
	if fb.callCount() != 1 {
		t.Errorf("SetBypass called %d times, want 1 (idempotent while failed)", fb.callCount())
	}
	if c.ProbeFailures() != 4 {
		t.Errorf("ProbeFailures = %d, want 4", c.ProbeFailures())
	}
}

func TestChecker_ClearsBypassOnRecovery(t *testing.T) {
	var fail bool
	q := func(ctx context.Context, server, name string, to time.Duration) error {
		if fail {
			return context.DeadlineExceeded
		}
		return nil
	}
	c, fb := newTestChecker(t, 2, q)
	ctx := context.Background()

	fail = true
	c.probeOnce(ctx, "10.0.0.2:53")
	c.probeOnce(ctx, "10.0.0.2:53") // bypass on
	if on, _ := fb.lastCall(); !on {
		t.Fatalf("expected bypass on")
	}

	fail = false
	c.probeOnce(ctx, "10.0.0.2:53") // recovery -> bypass off
	on, ok := fb.lastCall()
	if !ok || on {
		t.Fatalf("expected bypass=false after recovery, calls=%v", fb.calls)
	}
	if c.BypassActive() {
		t.Error("BypassActive() = true after recovery")
	}
}

func TestChecker_NoBypassWhenHealthy(t *testing.T) {
	healthy := func(ctx context.Context, server, name string, to time.Duration) error {
		return nil
	}
	c, fb := newTestChecker(t, 3, healthy)
	ctx := context.Background()
	for range 5 {
		c.probeOnce(ctx, "10.0.0.2:53")
	}
	if fb.callCount() != 0 {
		t.Errorf("SetBypass called while healthy: %v", fb.calls)
	}
	if c.ProbeFailures() != 0 {
		t.Errorf("ProbeFailures = %d, want 0", c.ProbeFailures())
	}
}

func TestChecker_SingleFailureThenRecoverNoFlap(t *testing.T) {
	var fail bool
	q := func(ctx context.Context, server, name string, to time.Duration) error {
		if fail {
			return context.DeadlineExceeded
		}
		return nil
	}
	c, fb := newTestChecker(t, 3, q)
	ctx := context.Background()

	fail = true
	c.probeOnce(ctx, "10.0.0.2:53") // 1 failure (< threshold)
	fail = false
	c.probeOnce(ctx, "10.0.0.2:53") // success resets counter
	if fb.callCount() != 0 {
		t.Errorf("bypass toggled on a single sub-threshold failure: %v", fb.calls)
	}
	if c.consecutiveFailures != 0 {
		t.Errorf("consecutiveFailures = %d, want 0 after success", c.consecutiveFailures)
	}
}

// Integration-style: a real miekg/dns server. Verifies udpQuery returns
// nil against a live responder and errors against a dead address.
func TestUDPQuery_AgainstLocalServer(t *testing.T) {
	addr, shutdown := startTestDNS(t)
	defer shutdown()

	ctx := context.Background()
	if err := udpQuery(ctx, addr, "amazon.com.", 2*time.Second); err != nil {
		t.Errorf("udpQuery against live server: %v", err)
	}

	// Unreachable port: expect error.
	if err := udpQuery(ctx, "127.0.0.1:1", "amazon.com.", 500*time.Millisecond); err == nil {
		t.Error("udpQuery against dead address: expected error, got nil")
	}
}
