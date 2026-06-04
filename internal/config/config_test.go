package config

import (
	"strings"
	"testing"
	"time"
)

const validYAML = `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - pattern: "*.s3.amazonaws.com"
    action: host-resolve
  - pattern: "*.dkr.ecr.us-west-2.amazonaws.com"
    action: host-resolve
metricsAddr: ":9153"
healthCheck:
  interval: 5s
  timeout: 2s
  failureThreshold: 3
logLevel: info
`

func TestParseValid(t *testing.T) {
	c, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.CorednsServiceIP != "10.100.0.10" {
		t.Errorf("CorednsServiceIP = %q", c.CorednsServiceIP)
	}
	if c.HostResolverIP != "10.0.0.2" {
		t.Errorf("HostResolverIP = %q", c.HostResolverIP)
	}
	if len(c.Rules) != 2 {
		t.Errorf("rules len = %d, want 2", len(c.Rules))
	}
	want := []string{"*.s3.amazonaws.com", "*.dkr.ecr.us-west-2.amazonaws.com"}
	got := c.Patterns()
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Patterns()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if c.HealthCheckInterval() != 5*time.Second {
		t.Errorf("interval = %s", c.HealthCheckInterval())
	}
}

func TestApplyDefaults(t *testing.T) {
	yaml := `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - pattern: "*.s3.amazonaws.com"
    action: host-resolve
`
	c, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.MetricsAddr != DefaultMetricsAddr {
		t.Errorf("MetricsAddr = %q, want default", c.MetricsAddr)
	}
	if c.HealthCheckInterval() != DefaultHealthCheckInterval {
		t.Errorf("interval = %s, want default", c.HealthCheckInterval())
	}
	if c.HealthCheckTimeout() != DefaultHealthCheckTimeout {
		t.Errorf("timeout = %s, want default", c.HealthCheckTimeout())
	}
	if c.HealthCheckThreshold() != DefaultHealthCheckThreshold {
		t.Errorf("threshold = %d, want default", c.HealthCheckThreshold())
	}
	if c.LogLevel != DefaultLogLevel {
		t.Errorf("loglevel = %q, want default", c.LogLevel)
	}
}

type errCase struct {
	name string
	yaml string
	want string
}

func TestParseRejects(t *testing.T) {
	cases := []errCase{
		{"missing corednsServiceIP", `
hostResolverIP: "10.0.0.2"
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
`, "corednsServiceIP is required"},
		{"missing hostResolverIP", `
corednsServiceIP: "10.100.0.10"
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
`, "hostResolverIP is required"},
		{"loopback hostResolverIP", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "127.0.0.53"
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
`, "loopback"},
		{"bad ip format", `
corednsServiceIP: "not-an-ip"
hostResolverIP: "10.0.0.2"
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
`, "not a valid IP"},
		{"ipv6 hostResolverIP", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "fd00::1"
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
`, "not IPv4"},
		{"empty rules", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
`, "at least one rule"},
		{"non-wildcard pattern", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - { pattern: "s3.amazonaws.com", action: host-resolve }
`, "must start with *."},
		{"interior wildcard", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - { pattern: "*.s3.*.amazonaws.com", action: host-resolve }
`, "interior wildcard"},
		{"unsupported action", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - { pattern: "*.s3.amazonaws.com", action: drop }
`, "unsupported action"},
		{"empty pattern", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - { pattern: "", action: host-resolve }
`, "pattern is empty"},
		{"label too long", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - { pattern: "*.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.amazonaws.com", action: host-resolve }
`, "exceeding 63"},
		{"empty label", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - { pattern: "*..amazonaws.com", action: host-resolve }
`, "empty label"},
		{"explicit zero interval", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
healthCheck: { interval: 0s }
`, "interval must be > 0"},
		{"explicit zero timeout", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
healthCheck: { timeout: 0s }
`, "timeout must be > 0"},
		{"explicit zero threshold", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
healthCheck: { failureThreshold: 0 }
`, "failureThreshold must be >= 1"},
		{"healthcheck timeout >= interval", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
healthCheck: { interval: 2s, timeout: 5s, failureThreshold: 3 }
`, "must be <"},
		{"bad metricsAddr", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
metricsAddr: "not-a-host-port"
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
`, "metricsAddr"},
		{"non-numeric port", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
metricsAddr: ":abc"
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
`, "not numeric"},
		{"port out of range", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
metricsAddr: ":99999"
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
`, "out of range"},
		{"port zero", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
metricsAddr: ":0"
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
`, "out of range"},
		{"bad logLevel", `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
logLevel: trace
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
`, "invalid logLevel"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q; want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestUnknownFieldsIgnored(t *testing.T) {
	yaml := `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - { pattern: "*.s3.amazonaws.com", action: host-resolve }
unknownField: 42
`
	if _, err := Parse([]byte(yaml)); err != nil {
		t.Errorf("unexpected error parsing yaml with unknown field: %v", err)
	}
}
