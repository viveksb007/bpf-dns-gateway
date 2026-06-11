// Package health probes the VPC DNS resolver and toggles the eBPF
// bypass flag so DNS keeps working through CoreDNS when the resolver is
// unreachable.
//
// Failure semantics (design.md §7.5):
//   - N consecutive probe failures -> set bypass=1 (ingress stops DNAT).
//   - 1 success after being failed   -> clear bypass=0.
package health

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// BypassSetter is the subset of the loader the checker needs. The
// controller's loader satisfies it.
type BypassSetter interface {
	SetBypass(on bool) error
}

// Config controls probe behavior.
type Config struct {
	// ResolverIP is the VPC DNS resolver to probe (IPv4).
	ResolverIP net.IP
	// ProbePort is the resolver UDP port. Defaults to 53. Overridable
	// for tests that stand up a local DNS responder on a random port.
	ProbePort int
	// ProbeName is the DNS name queried (A record). Defaults to
	// "amazon.com." if empty.
	ProbeName string
	// Interval between probes.
	Interval time.Duration
	// Timeout for a single probe.
	Timeout time.Duration
	// FailureThreshold consecutive failures before bypass is enabled.
	FailureThreshold int
}

// queryFunc performs one DNS probe. Swapped out in tests.
type queryFunc func(ctx context.Context, server, name string, timeout time.Duration) error

// Checker periodically probes the resolver and flips bypass.
type Checker struct {
	cfg     Config
	bypass  BypassSetter
	logger  *slog.Logger
	query   queryFunc
	onState func(bypassOn bool) // optional hook (metrics/tests)

	// consecutiveFailures is only touched from the Run goroutine.
	consecutiveFailures int
	// bypassActive + probeFailures are also read by the metrics
	// collector goroutine, so they are atomic.
	bypassActive  atomic.Bool
	probeFailures atomic.Uint64
}

// New constructs a Checker. ResolverIP must be IPv4; Interval/Timeout/
// FailureThreshold must be positive (validated by config earlier, but
// re-checked here so the package is safe in isolation).
func New(cfg Config, bypass BypassSetter, logger *slog.Logger) (*Checker, error) {
	if bypass == nil {
		return nil, fmt.Errorf("BypassSetter is required")
	}
	if cfg.ResolverIP == nil || cfg.ResolverIP.To4() == nil {
		return nil, fmt.Errorf("ResolverIP must be IPv4")
	}
	if cfg.Interval <= 0 {
		return nil, fmt.Errorf("Interval must be > 0")
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("Timeout must be > 0")
	}
	if cfg.FailureThreshold < 1 {
		return nil, fmt.Errorf("FailureThreshold must be >= 1")
	}
	if cfg.ProbePort < 0 || cfg.ProbePort > 65535 {
		return nil, fmt.Errorf("ProbePort %d out of range (want 1..65535)", cfg.ProbePort)
	}
	if cfg.ProbeName == "" {
		cfg.ProbeName = "amazon.com."
	}
	if cfg.ProbePort == 0 {
		cfg.ProbePort = 53
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Checker{
		cfg:    cfg,
		bypass: bypass,
		logger: logger,
		query:  udpQuery,
	}, nil
}

// Run probes on a ticker until ctx is canceled. It does one immediate
// probe on entry so startup bad-resolver state is detected without
// waiting a full interval.
func (c *Checker) Run(ctx context.Context) error {
	server := net.JoinHostPort(c.cfg.ResolverIP.String(), strconv.Itoa(c.cfg.ProbePort))

	c.probeOnce(ctx, server)

	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.probeOnce(ctx, server)
		}
	}
}

// ProbeFailures returns the cumulative count of failed probes (for the
// metrics collector). Safe to call from any goroutine.
func (c *Checker) ProbeFailures() uint64 { return c.probeFailures.Load() }

// BypassActive reports the last-applied bypass state. Safe to call from
// any goroutine.
func (c *Checker) BypassActive() bool { return c.bypassActive.Load() }

func (c *Checker) probeOnce(ctx context.Context, server string) {
	err := c.query(ctx, server, c.cfg.ProbeName, c.cfg.Timeout)
	if err != nil {
		c.probeFailures.Add(1)
		c.consecutiveFailures++
		c.logger.Warn("health probe failed",
			"server", server,
			"consecutive", c.consecutiveFailures,
			"threshold", c.cfg.FailureThreshold,
			"err", err,
		)
		if c.consecutiveFailures >= c.cfg.FailureThreshold && !c.bypassActive.Load() {
			if serr := c.bypass.SetBypass(true); serr != nil {
				c.logger.Error("failed to enable bypass", "err", serr)
				return
			}
			c.bypassActive.Store(true)
			c.logger.Warn("bypass ENABLED: VPC DNS resolver unhealthy", "server", server)
			if c.onState != nil {
				c.onState(true)
			}
		}
		return
	}

	// Success.
	c.consecutiveFailures = 0
	if c.bypassActive.Load() {
		if serr := c.bypass.SetBypass(false); serr != nil {
			c.logger.Error("failed to clear bypass", "err", serr)
			return
		}
		c.bypassActive.Store(false)
		c.logger.Info("bypass CLEARED: VPC DNS resolver recovered", "server", server)
		if c.onState != nil {
			c.onState(false)
		}
	}
}

// udpQuery sends a single A query over UDP and returns nil on any valid
// DNS response (even NXDOMAIN/SERVFAIL — the resolver answered, which is
// what we care about for health).
func udpQuery(ctx context.Context, server, name string, timeout time.Duration) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true

	cl := &dns.Client{Net: "udp"}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, _, err := cl.ExchangeContext(probeCtx, m, server)
	if err != nil {
		return err
	}
	if resp == nil {
		return fmt.Errorf("nil DNS response")
	}
	// Any RCODE is fine — the resolver responded.
	return nil
}
