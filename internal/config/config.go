// Package config loads and validates the bpf-dns-gateway YAML config
// file. The schema mirrors docs/design.md §8.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Defaults applied when the YAML omits a field.
const (
	DefaultMetricsAddr           = ":9153"
	DefaultHealthCheckInterval   = 5 * time.Second
	DefaultHealthCheckTimeout    = 2 * time.Second
	DefaultHealthCheckThreshold  = 3
	DefaultLogLevel              = "info"
)

// Rule is a single suffix-match entry.
type Rule struct {
	Pattern string `yaml:"pattern"`
	Action  string `yaml:"action"`
}

// HealthCheck controls VPC DNS probe behavior. Pointer fields let us
// distinguish "field omitted in YAML" (apply default) from "explicit
// zero" (rejected by Validate).
type HealthCheck struct {
	Interval         *time.Duration `yaml:"interval,omitempty"`
	Timeout          *time.Duration `yaml:"timeout,omitempty"`
	FailureThreshold *int           `yaml:"failureThreshold,omitempty"`
}

// Config is the top-level YAML schema.
type Config struct {
	CorednsServiceIP string      `yaml:"corednsServiceIP"`
	HostResolverIP   string      `yaml:"hostResolverIP"`
	Rules            []Rule      `yaml:"rules"`
	MetricsAddr      string      `yaml:"metricsAddr"`
	HealthCheck      HealthCheck `yaml:"healthCheck"`
	LogLevel         string      `yaml:"logLevel"`
}

// HealthCheckInterval returns the resolved interval (default applied
// only if the field was omitted; explicit zero is preserved so
// Validate can reject it).
func (c *Config) HealthCheckInterval() time.Duration {
	if c.HealthCheck.Interval == nil {
		return DefaultHealthCheckInterval
	}
	return *c.HealthCheck.Interval
}

// HealthCheckTimeout returns the resolved timeout.
func (c *Config) HealthCheckTimeout() time.Duration {
	if c.HealthCheck.Timeout == nil {
		return DefaultHealthCheckTimeout
	}
	return *c.HealthCheck.Timeout
}

// HealthCheckThreshold returns the resolved threshold.
func (c *Config) HealthCheckThreshold() int {
	if c.HealthCheck.FailureThreshold == nil {
		return DefaultHealthCheckThreshold
	}
	return *c.HealthCheck.FailureThreshold
}

// Load reads and validates the YAML file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses raw YAML bytes into a Config and validates.
func Parse(data []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.MetricsAddr == "" {
		c.MetricsAddr = DefaultMetricsAddr
	}
	if c.LogLevel == "" {
		c.LogLevel = DefaultLogLevel
	}
	// HealthCheck defaults are applied via the accessor helpers
	// (HealthCheckInterval, etc.) so explicit zero values from YAML
	// reach Validate and get rejected rather than silently defaulted.
}

// Validate enforces the schema constraints.
func (c *Config) Validate() error {
	if c.CorednsServiceIP == "" {
		return fmt.Errorf("corednsServiceIP is required")
	}
	if err := validateIPv4(c.CorednsServiceIP, "corednsServiceIP", false); err != nil {
		return err
	}
	if c.HostResolverIP == "" {
		return fmt.Errorf("hostResolverIP is required (no /etc/resolv.conf auto-detect; nodes running systemd-resolved expose 127.0.0.53 which is unusable)")
	}
	if err := validateIPv4(c.HostResolverIP, "hostResolverIP", true); err != nil {
		return err
	}
	if len(c.Rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}
	for i, r := range c.Rules {
		if err := validateRule(r); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	if err := validateMetricsAddr(c.MetricsAddr); err != nil {
		return err
	}
	interval := c.HealthCheckInterval()
	timeout := c.HealthCheckTimeout()
	threshold := c.HealthCheckThreshold()
	if interval <= 0 {
		return fmt.Errorf("healthCheck.interval must be > 0 (got %s)", interval)
	}
	if timeout <= 0 {
		return fmt.Errorf("healthCheck.timeout must be > 0 (got %s)", timeout)
	}
	if timeout >= interval {
		return fmt.Errorf("healthCheck.timeout (%s) must be < healthCheck.interval (%s)", timeout, interval)
	}
	if threshold < 1 {
		return fmt.Errorf("healthCheck.failureThreshold must be >= 1 (got %d)", threshold)
	}
	if !validLogLevel(c.LogLevel) {
		return fmt.Errorf("invalid logLevel %q (want debug|info|warn|error)", c.LogLevel)
	}
	return nil
}

// Patterns returns the suffix patterns from c.Rules in input order.
func (c *Config) Patterns() []string {
	out := make([]string, len(c.Rules))
	for i, r := range c.Rules {
		out[i] = r.Pattern
	}
	return out
}

func validateIPv4(s, field string, rejectLoopback bool) error {
	ip := net.ParseIP(s)
	if ip == nil {
		return fmt.Errorf("%s: %q is not a valid IP", field, s)
	}
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("%s: %q is not IPv4", field, s)
	}
	if rejectLoopback && v4.IsLoopback() {
		return fmt.Errorf("%s: %q is a loopback address; use the VPC DNS resolver IP (e.g. VPC CIDR base + 2)", field, s)
	}
	if v4.IsUnspecified() {
		return fmt.Errorf("%s: %q is the unspecified address", field, s)
	}
	if v4.IsMulticast() {
		return fmt.Errorf("%s: %q is a multicast address", field, s)
	}
	return nil
}

func validateRule(r Rule) error {
	if r.Pattern == "" {
		return fmt.Errorf("pattern is empty")
	}
	if !strings.HasPrefix(r.Pattern, "*.") {
		return fmt.Errorf("pattern %q must start with *. (exact match unsupported in MVP)", r.Pattern)
	}
	suffix := strings.TrimPrefix(r.Pattern, "*.")
	if strings.Contains(suffix, "*") {
		return fmt.Errorf("pattern %q has interior wildcard; only leading *.suffix is supported", r.Pattern)
	}
	if suffix == "" {
		return fmt.Errorf("pattern %q has empty suffix", r.Pattern)
	}
	for _, label := range strings.Split(suffix, ".") {
		if label == "" {
			return fmt.Errorf("pattern %q has empty label", r.Pattern)
		}
		if len(label) > 63 {
			return fmt.Errorf("pattern %q has label %q exceeding 63 bytes", r.Pattern, label)
		}
	}
	if r.Action == "" {
		return fmt.Errorf("pattern %q action is empty", r.Pattern)
	}
	if r.Action != "host-resolve" {
		return fmt.Errorf("pattern %q has unsupported action %q (only host-resolve in MVP)", r.Pattern, r.Action)
	}
	return nil
}

func validateMetricsAddr(addr string) error {
	if addr == "" {
		return fmt.Errorf("metricsAddr is empty")
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("metricsAddr %q: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("metricsAddr %q: empty port", addr)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("metricsAddr %q: port %q is not numeric", addr, port)
	}
	// 0 is valid (kernel picks an ephemeral port) but useless for a
	// metrics listener consumers need to scrape; reject as an obvious
	// misconfiguration. Range upper bound is 65535.
	if p < 1 || p > 65535 {
		return fmt.Errorf("metricsAddr %q: port %d out of range (want 1..65535)", addr, p)
	}
	return nil
}

func validLogLevel(s string) bool {
	switch s {
	case "debug", "info", "warn", "error":
		return true
	}
	return false
}
