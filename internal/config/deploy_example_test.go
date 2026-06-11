package config

import "testing"

// TestDeployExampleConfigValid ensures the shipped deploy/config.yaml
// stays valid against the parser. Guards against schema drift.
func TestDeployExampleConfigValid(t *testing.T) {
	c, err := Load("../../deploy/config.yaml")
	if err != nil {
		t.Fatalf("deploy/config.yaml invalid: %v", err)
	}
	if len(c.Rules) == 0 {
		t.Error("deploy/config.yaml has no rules")
	}
}
