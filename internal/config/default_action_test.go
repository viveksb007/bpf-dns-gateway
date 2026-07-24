package config

import (
	"strings"
	"testing"
)

// Task 22 (design.md §8/§8.1): defaultAction + cluster-resolve action.

func TestDefaultAction_OmittedDefaultsToClusterResolve(t *testing.T) {
	// validYAML has no defaultAction — existing configs must keep the
	// pre-feature behavior.
	c, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.DefaultAction != ActionClusterResolve {
		t.Errorf("DefaultAction = %q, want %q", c.DefaultAction, ActionClusterResolve)
	}
}

func TestDefaultAction_HostResolveMode(t *testing.T) {
	yaml := `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
defaultAction: host-resolve
rules:
  - pattern: "*.cluster.local"
    action: cluster-resolve
  - pattern: "*.in-addr.arpa"
    action: cluster-resolve
`
	c, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.DefaultAction != ActionHostResolve {
		t.Errorf("DefaultAction = %q, want %q", c.DefaultAction, ActionHostResolve)
	}
	for i, r := range c.Rules {
		if r.Action != ActionClusterResolve {
			t.Errorf("rules[%d].Action = %q, want %q", i, r.Action, ActionClusterResolve)
		}
	}
}

func TestDefaultAction_MixedActionsBothModes(t *testing.T) {
	yaml := `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
defaultAction: cluster-resolve
rules:
  - pattern: "*.amazonaws.com"
    action: host-resolve
  - pattern: "*.s3.amazonaws.com"
    action: cluster-resolve
`
	if _, err := Parse([]byte(yaml)); err != nil {
		t.Errorf("mixed actions with cluster-resolve default: %v", err)
	}
}

func TestDefaultAction_InvalidValueRejected(t *testing.T) {
	yaml := `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
defaultAction: node-resolve
rules:
  - pattern: "*.s3.amazonaws.com"
    action: host-resolve
`
	_, err := Parse([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "defaultAction") {
		t.Errorf("expected defaultAction error, got %v", err)
	}
}

func TestDefaultAction_InvalidRuleActionRejected(t *testing.T) {
	yaml := `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
rules:
  - pattern: "*.s3.amazonaws.com"
    action: drop
`
	_, err := Parse([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "unsupported action") {
		t.Errorf("expected unsupported action error, got %v", err)
	}
}

func TestDefaultAction_HostResolveWithoutClusterRuleRejected(t *testing.T) {
	// The dangerous no-op: everything (including cluster service
	// discovery) would be sent to the VPC resolver.
	yaml := `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
defaultAction: host-resolve
rules:
  - pattern: "*.s3.amazonaws.com"
    action: host-resolve
`
	_, err := Parse([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "different from defaultAction") {
		t.Errorf("expected no-op config rejection, got %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "cluster.local") {
		t.Errorf("host-resolve rejection should hint at cluster breakage, got %v", err)
	}
}

func TestDefaultAction_AllRulesRestateClusterDefaultRejected(t *testing.T) {
	yaml := `
corednsServiceIP: "10.100.0.10"
hostResolverIP: "10.0.0.2"
defaultAction: cluster-resolve
rules:
  - pattern: "*.cluster.local"
    action: cluster-resolve
`
	_, err := Parse([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "different from defaultAction") {
		t.Errorf("expected no-op config rejection, got %v", err)
	}
}
