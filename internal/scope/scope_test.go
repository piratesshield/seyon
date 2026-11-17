package scope

import "testing"

func TestParseRequiresAllowActive(t *testing.T) {
	if _, err := Parse([]byte("targets:\n  - stdio:x\n")); err == nil {
		t.Error("a scope without allow_active must be refused")
	}
}

func TestParseRequiresTargets(t *testing.T) {
	if _, err := Parse([]byte("allow_active: true\n")); err == nil {
		t.Error("a scope with no targets must be refused")
	}
}

func TestParseMalformedIsRefused(t *testing.T) {
	if _, err := Parse([]byte("allow_active: : : not yaml")); err == nil {
		t.Error("a malformed scope must be refused, never permissive")
	}
}

func TestAuthorizesIsExact(t *testing.T) {
	s, err := Parse([]byte("allow_active: true\ntargets:\n  - \"stdio:/opt/srv\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Authorizes("stdio:/opt/srv") {
		t.Error("listed target should be authorized")
	}
	if s.Authorizes("stdio:/opt/other") {
		t.Error("unlisted target must not be authorized")
	}
}

func TestEgressDeniedDefaultsTrue(t *testing.T) {
	s, err := Parse([]byte("allow_active: true\ntargets:\n  - x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.EgressDenied() {
		t.Error("egress must default to denied when unset")
	}

	f := false
	s.DenyEgress = &f
	if s.EgressDenied() {
		t.Error("egress should be allowed when explicitly set false")
	}
}
