package health

import (
	"context"
	"net"
	"testing"
	"time"
)

// Regression test for the shutdown SetBypass race: main's shutdown path
// sets bypass=1 after canceling the lifecycle context, but a probe
// already in flight inside Checker.Run could complete afterwards and —
// via the recovery path — call SetBypass(false), clobbering the
// shutdown bypass while packets were still flowing.
//
// Pre-fix this test failed with calls=[true true false]. It models the
// worst-case ordering (bypass set immediately after cancel, before the
// in-flight probe completes); the probeOnce ctx guard must prevent any
// bypass mutation once shutdown has begun. main.go additionally waits
// on Checker.Done() before setting the teardown bypass (belt and
// suspenders; see TestChecker_DoneClosedAfterRunExits).
func TestShutdownRace_InFlightProbeClobbersShutdownBypass(t *testing.T) {
	fb := &fakeBypass{}

	probeStarted := make(chan struct{})
	probeRelease := make(chan struct{})
	q := func(ctx context.Context, server, name string, to time.Duration) error {
		select {
		case probeStarted <- struct{}{}:
		default:
		}
		<-probeRelease // block until "shutdown" has begun
		return nil     // resolver recovered
	}

	c, err := New(Config{
		ResolverIP:       net.ParseIP("10.0.0.2"),
		Interval:         50 * time.Millisecond,
		Timeout:          10 * time.Millisecond,
		FailureThreshold: 1,
	}, fb, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Drive the checker into bypass-active state (as if the resolver had
	// been down), without Run: one over-threshold failure.
	c.query = func(ctx context.Context, server, name string, to time.Duration) error {
		return context.DeadlineExceeded
	}
	c.probeOnce(context.Background(), "10.0.0.2:53")
	if !c.BypassActive() {
		t.Fatal("setup: bypass not active after threshold failure")
	}

	// Now run with the blocking "recovered" query.
	c.query = q
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		_ = c.Run(ctx)
		close(runDone)
	}()

	<-probeStarted // a probe is in flight

	// --- main.go shutdown path (worst-case ordering) ---
	cancel()               // lifecycle ctx canceled
	_ = fb.SetBypass(true) // set bypass=1 for teardown
	close(probeRelease)    // in-flight probe now completes "successfully"
	<-runDone              // checker loop exits

	// The shutdown bypass must survive.
	on, ok := fb.lastCall()
	if !ok || !on {
		t.Fatalf("shutdown bypass clobbered: final SetBypass call was %v (calls=%v); "+
			"in-flight probe cleared bypass after shutdown set it", on, fb.calls)
	}
}

// Done() must be closed only after Run has fully exited (no further
// SetBypass calls possible), so main can order "checker stopped" before
// setting the teardown bypass.
func TestChecker_DoneClosedAfterRunExits(t *testing.T) {
	healthy := func(ctx context.Context, server, name string, to time.Duration) error {
		return nil
	}
	c, _ := newTestChecker(t, 3, healthy)

	select {
	case <-c.Done():
		t.Fatal("Done() closed before Run started")
	default:
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = c.Run(ctx) }()
	cancel()

	select {
	case <-c.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done() not closed within 2s of ctx cancel")
	}
}
