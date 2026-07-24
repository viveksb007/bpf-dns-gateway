// Package controller orchestrates the eBPF loader, the netlink veth
// monitor, and the TCX attach manager. It owns the high-level lifecycle:
// load + populate maps + subscribe + attach to existing/new veths +
// cleanly detach on shutdown.
package controller

import (
	"context"
	"fmt"
	"log/slog"

	bpf "github.com/viveksb007/bpf-dns-gateway/internal/ebpf"
	"github.com/viveksb007/bpf-dns-gateway/internal/netlinkmon"
)

// Controller wires the loader/attach/monitor together.
type Controller struct {
	logger  *slog.Logger
	loader  *bpf.Loader
	mgr     *bpf.AttachManager
	monitor *netlinkmon.Monitor

	// Closed by Run when the loop exits so callers can wait on Done().
	done chan struct{}

	// Optional pre-attach hook for tests; nil in production.
	preAttachHook func(ifindex int)
}

// Options collects external dependencies for New.
type Options struct {
	Loader  *bpf.Loader
	Manager *bpf.AttachManager
	Monitor *netlinkmon.Monitor
	Logger  *slog.Logger
}

// New constructs a Controller. All Options fields are required.
func New(opts Options) (*Controller, error) {
	if opts.Loader == nil {
		return nil, fmt.Errorf("Loader is required")
	}
	if opts.Manager == nil {
		return nil, fmt.Errorf("Manager is required")
	}
	if opts.Monitor == nil {
		return nil, fmt.Errorf("Monitor is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Controller{
		logger:  logger,
		loader:  opts.Loader,
		mgr:     opts.Manager,
		monitor: opts.Monitor,
		done:    make(chan struct{}),
	}, nil
}

// Run consumes monitor events until ctx is canceled. On EventAdd the
// program pair is attached to the ifindex; on EventRemove the local
// tracking is cleared (TCX auto-detaches when the link goes away).
//
// Run does NOT start the monitor — the caller is expected to start it
// in its own goroutine alongside Run.
func (c *Controller) Run(ctx context.Context) error {
	defer close(c.done)

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("controller stopping; detaching from all interfaces")
			return c.detachAll()
		case ev, ok := <-c.monitor.Events():
			if !ok {
				// Distinguish clean shutdown (ctx already
				// canceled, monitor close is just downstream
				// of that) from a real netlink failure where
				// ctx is still alive.
				if ctx.Err() != nil {
					c.logger.Info("controller stopping; detaching from all interfaces")
					return c.detachAll()
				}
				c.logger.Error("monitor events channel closed unexpectedly; detaching from all interfaces")
				if err := c.detachAll(); err != nil {
					return fmt.Errorf("monitor exited unexpectedly; detach also failed: %w", err)
				}
				return fmt.Errorf("monitor exited unexpectedly")
			}
			c.handle(ev)
		}
	}
}

// Done returns a channel that is closed when Run exits. Useful for
// tests and graceful shutdown.
func (c *Controller) Done() <-chan struct{} { return c.done }

// SetBypass forwards to the loader. Defined here so the controller is
// the single facade callers go through for runtime state changes.
func (c *Controller) SetBypass(on bool) error {
	if err := c.loader.SetBypass(on); err != nil {
		return fmt.Errorf("set bypass=%v: %w", on, err)
	}
	c.logger.Info("bypass updated", "on", on)
	return nil
}

// AttachedCount returns the number of currently-attached interfaces.
func (c *Controller) AttachedCount() int { return c.mgr.AttachedCount() }

func (c *Controller) handle(ev netlinkmon.Event) {
	if c.preAttachHook != nil {
		c.preAttachHook(ev.Ifindex)
	}
	switch ev.Type {
	case netlinkmon.EventAdd:
		if err := c.mgr.Attach(ev.Ifindex); err != nil {
			c.logger.Error("attach failed",
				"ifindex", ev.Ifindex,
				"name", ev.Name,
				"err", err,
			)
			return
		}
		c.logger.Info("attached to veth", "ifindex", ev.Ifindex, "name", ev.Name)
	case netlinkmon.EventRemove:
		// TCX programs auto-detach when the underlying link goes
		// away. Detach() here only releases our local tracking.
		if err := c.mgr.Detach(ev.Ifindex); err != nil {
			c.logger.Warn("detach bookkeeping failed",
				"ifindex", ev.Ifindex,
				"name", ev.Name,
				"err", err,
			)
			return
		}
		c.logger.Info("detached from veth", "ifindex", ev.Ifindex, "name", ev.Name)
	}
}

func (c *Controller) detachAll() error {
	if err := c.mgr.DetachAll(); err != nil {
		return fmt.Errorf("detach all: %w", err)
	}
	return nil
}
