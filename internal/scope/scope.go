// Package scope encodes the written authorization required before Seyon does
// any active probing. Active probing invokes a target's tools, so it is refused
// unless a scope file explicitly enables it and names the target. This is the
// safety gate that keeps black-box scanning safe-by-default: without a scope,
// the engine only connects and enumerates.
package scope

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scope is a parsed authorization file.
type Scope struct {
	// AllowActive must be true for any tool invocation to occur. A scope that
	// lists targets but leaves this false still forbids active probing.
	AllowActive bool `yaml:"allow_active"`
	// Targets is the allowlist of authorized target identifiers (an endpoint URL,
	// a stdio command line, or a raw spec string). A target not listed is refused.
	Targets []string `yaml:"targets"`
	// DenyEgress, when true (the default), requires that spawned targets be run
	// with outbound network denied. The engine records this intent; it does not
	// by itself sandbox the host network.
	DenyEgress *bool `yaml:"deny_egress"`
	// MaxCallsPerTool bounds how many times the prober may invoke a single tool,
	// so probing cannot turn into a load test. Zero means the built-in default.
	MaxCallsPerTool int `yaml:"max_calls_per_tool"`
}

// Parse reads a scope file. An empty or malformed file is an error rather than
// a permissive default: failing to parse a scope must never enable probing.
func Parse(b []byte) (*Scope, error) {
	var s Scope
	if err := yaml.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("scope: parse: %w", err)
	}
	if !s.AllowActive {
		return nil, fmt.Errorf("scope: allow_active is not set; active probing is refused")
	}
	if len(s.Targets) == 0 {
		return nil, fmt.Errorf("scope: no targets listed; active probing is refused")
	}
	return &s, nil
}

// EgressDenied reports the effective egress posture: denied unless the scope
// explicitly sets deny_egress to false.
func (s *Scope) EgressDenied() bool {
	return s.DenyEgress == nil || *s.DenyEgress
}

// Authorizes reports whether target is covered by this scope. Matching is exact
// after trimming surrounding whitespace, so a typo fails closed.
func (s *Scope) Authorizes(target string) bool {
	target = strings.TrimSpace(target)
	for _, t := range s.Targets {
		if strings.TrimSpace(t) == target {
			return true
		}
	}
	return false
}
