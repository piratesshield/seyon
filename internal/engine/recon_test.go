package engine

import (
	"errors"
	"fmt"
	"testing"

	"seyon/internal/findings"
	"seyon/internal/mcp"
)

func TestReconClassifiesHandshakeFailures(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		ruleID   string
		severity findings.Severity
	}{
		{"auth required", &mcp.HTTPStatusError{Code: 401, Body: `{"error":"invalid_token"}`}, "A.endpoint.auth-required", findings.SeverityInfo},
		{"forbidden", &mcp.HTTPStatusError{Code: 403}, "A.endpoint.auth-required", findings.SeverityInfo},
		{"not found", &mcp.HTTPStatusError{Code: 404, Body: "Not Found"}, "A.endpoint.not-found", findings.SeverityInfo},
		{"rate limited", &mcp.HTTPStatusError{Code: 429}, "A.endpoint.rate-limited", findings.SeverityInfo},
		{"server error", &mcp.HTTPStatusError{Code: 502}, "A.endpoint.server-error", findings.SeverityLow},
		{"other 4xx", &mcp.HTTPStatusError{Code: 418}, "A.handshake.rejected", findings.SeverityInfo},
		{"transport", errors.New("dial tcp: connection refused"), "A.transport.unreachable", findings.SeverityInfo},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := reconFromError(c.err, "https://target.example/mcp")
			if len(fs) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(fs))
			}
			f := fs[0]
			if f.RuleID != c.ruleID {
				t.Errorf("rule id: got %q want %q", f.RuleID, c.ruleID)
			}
			if f.Class != "A" {
				t.Errorf("class: got %q want A", f.Class)
			}
			if f.Severity != c.severity {
				t.Errorf("severity: got %q want %q", f.Severity, c.severity)
			}
			if f.Target.Endpoint != "https://target.example/mcp" {
				t.Errorf("endpoint not set on finding: %+v", f.Target)
			}
			if err := f.Validate(); err != nil {
				t.Errorf("recon finding fails schema validation: %v", err)
			}
		})
	}
}

// TestReconWrappedError confirms a wrapped HTTPStatusError is still classified
// (Enumerate wraps transport errors with fmt.Errorf("...: %w", err)).
func TestReconWrappedError(t *testing.T) {
	err := fmt.Errorf("enumerate tools: %w", &mcp.HTTPStatusError{Code: 401})
	fs := reconFromError(err, "https://x/mcp")
	if len(fs) != 1 || fs[0].RuleID != "A.endpoint.auth-required" {
		t.Errorf("wrapped 401 should classify as auth-required, got %+v", fs)
	}
}
