// Package netlinkmon discovers veth interfaces by subscribing to
// netlink RTM_NEWLINK / RTM_DELLINK events.
//
// The controller starts the monitor first, then enumerates existing
// veths, deduplicating by ifindex. ListExisting=true on the netlink
// subscription causes the kernel to replay current links via the same
// channel, which closes the race between subscribe and enumerate.
package netlinkmon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Event is emitted when a veth interface appears or disappears.
type Event struct {
	Type    EventType
	Ifindex int
	Name    string
}

// EventType discriminates Event.
type EventType int

const (
	// EventAdd is emitted when a veth ifindex first becomes visible.
	EventAdd EventType = iota
	// EventRemove is emitted when an ifindex disappears.
	EventRemove
)

func (t EventType) String() string {
	switch t {
	case EventAdd:
		return "add"
	case EventRemove:
		return "remove"
	}
	return "unknown"
}

// Monitor subscribes to RTNLGRP_LINK and emits Add/Remove events for
// veth interfaces.
type Monitor struct {
	logger *slog.Logger
	mu     sync.Mutex
	known  map[int]string
	events chan Event
}

// New constructs a Monitor with the given logger. nil uses slog.Default.
func New(logger *slog.Logger) *Monitor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Monitor{
		logger: logger,
		known:  make(map[int]string),
		events: make(chan Event, 32),
	}
}

// Events returns the read-side of the event channel. Closed when Start
// returns (after ctx is canceled or netlink errors).
func (m *Monitor) Events() <-chan Event {
	return m.events
}

// Start subscribes to RTM_NEWLINK / RTM_DELLINK with ListExisting=true
// so existing veths arrive via the same channel that future events do.
// Blocks until ctx is canceled or netlink errors.
func (m *Monitor) Start(ctx context.Context) error {
	defer close(m.events)

	updates := make(chan netlink.LinkUpdate, 64)
	done := make(chan struct{})
	defer close(done)

	// Fatal errors set lastFatalErr. Non-fatal errors (e.g.
	// ErrDumpInterrupted during the initial ListExisting dump) are
	// only logged so a busy host doesn't tear down monitoring, but we
	// also flip dumpInterrupted so the loop can resync via an explicit
	// LinkList() afterwards.
	var (
		lastFatalErrMu   sync.Mutex
		lastFatalErr     error
		dumpInterrupted  atomic.Bool
	)
	opts := netlink.LinkSubscribeOptions{
		ListExisting: true,
		ErrorCallback: func(err error) {
			// During shutdown the socket read is interrupted as the
			// subscription is torn down (EAGAIN / "resource
			// temporarily unavailable"). That is expected, not a
			// fault — suppress it once ctx is canceled.
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, netlink.ErrDumpInterrupted) {
				m.logger.Warn("netlink dump interrupted; will resync via LinkList", "err", err)
				dumpInterrupted.Store(true)
				return
			}
			m.logger.Error("netlink subscription error", "err", err)
			lastFatalErrMu.Lock()
			lastFatalErr = err
			lastFatalErrMu.Unlock()
		},
	}
	if err := netlink.LinkSubscribeWithOptions(updates, done, opts); err != nil {
		return fmt.Errorf("netlink LinkSubscribe: %w", err)
	}

	getFatal := func() error {
		lastFatalErrMu.Lock()
		defer lastFatalErrMu.Unlock()
		return lastFatalErr
	}

	// Resync goroutine: when the initial ListExisting dump is
	// reported as interrupted, explicitly enumerate links and emit
	// Adds for any veth we have not already seen. Exits on ctx.Done
	// OR when the main loop signals stopResync (e.g. on subscription
	// failure with ctx still alive).
	resyncDone := make(chan struct{})
	stopResync := make(chan struct{})
	go func() {
		defer close(resyncDone)
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopResync:
				return
			case <-time.After(50 * time.Millisecond):
			}
			if !dumpInterrupted.Load() {
				continue
			}
			links, err := netlink.LinkList()
			if err != nil {
				if errors.Is(err, netlink.ErrDumpInterrupted) {
					continue
				}
				m.logger.Error("resync LinkList failed", "err", err)
				continue
			}
			dumpInterrupted.Store(false)
			for _, l := range links {
				if l.Type() != "veth" {
					continue
				}
				attrs := l.Attrs()
				if attrs == nil {
					continue
				}
				m.mu.Lock()
				if _, already := m.known[attrs.Index]; already {
					m.mu.Unlock()
					continue
				}
				m.known[attrs.Index] = attrs.Name
				m.mu.Unlock()
				if !m.emit(ctx, stopResync, Event{Type: EventAdd, Ifindex: attrs.Index, Name: attrs.Name}) {
					return
				}
			}
		}
	}()
	defer func() {
		close(stopResync)
		<-resyncDone
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case u, ok := <-updates:
			if !ok {
				// updates is closed when the subscription loop
				// exits. Surface the most recent fatal error if
				// any. ctx-cancel path returned earlier.
				if err := getFatal(); err != nil {
					return fmt.Errorf("netlink subscription error: %w", err)
				}
				return fmt.Errorf("netlink updates channel closed unexpectedly")
			}
			if !m.handle(ctx, stopResync, u) {
				// Cancellation observed while emitting.
				return nil
			}
		}
	}
}

// handle classifies a single LinkUpdate and emits an Event if the
// interface is a veth and the event represents a state change. Returns
// false if ctx or stop fired while emitting (Start should exit).
func (m *Monitor) handle(ctx context.Context, stop <-chan struct{}, u netlink.LinkUpdate) bool {
	if u.Link == nil {
		return true
	}
	attrs := u.Link.Attrs()
	if attrs == nil {
		return true
	}
	ifindex := attrs.Index

	switch u.Header.Type {
	case unix.RTM_NEWLINK:
		// Filter by link kind. Only veths participate in the pod
		// network path on EKS.
		if u.Link.Type() != "veth" {
			return true
		}
		m.mu.Lock()
		if _, already := m.known[ifindex]; already {
			m.mu.Unlock()
			return true
		}
		m.known[ifindex] = attrs.Name
		m.mu.Unlock()
		return m.emit(ctx, stop, Event{Type: EventAdd, Ifindex: ifindex, Name: attrs.Name})

	case unix.RTM_DELLINK:
		m.mu.Lock()
		name, ok := m.known[ifindex]
		if !ok {
			m.mu.Unlock()
			return true
		}
		delete(m.known, ifindex)
		m.mu.Unlock()
		return m.emit(ctx, stop, Event{Type: EventRemove, Ifindex: ifindex, Name: name})
	}
	return true
}

// emit sends ev on m.events. Returns false if ctx is canceled OR the
// monitor's internal stop signal is set before the send completes. We
// MUST NOT drop add/remove events while running, so the only way out
// without sending is shutdown.
func (m *Monitor) emit(ctx context.Context, stop <-chan struct{}, ev Event) bool {
	m.logger.Info("veth event",
		"type", ev.Type.String(),
		"ifindex", ev.Ifindex,
		"name", ev.Name,
	)
	select {
	case m.events <- ev:
		return true
	case <-ctx.Done():
		return false
	case <-stop:
		return false
	}
}

// KnownIfindexes returns a snapshot of currently-tracked veth ifindexes.
// Useful for tests and shutdown bookkeeping.
func (m *Monitor) KnownIfindexes() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]int, 0, len(m.known))
	for i := range m.known {
		out = append(out, i)
	}
	return out
}
