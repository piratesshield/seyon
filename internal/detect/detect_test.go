package detect

import (
	"path/filepath"
	"testing"

	"seyon/internal/findings"
	"seyon/internal/mcp"
	"seyon/internal/surface"
)

// TestExternalRulePackExtendsBuiltins confirms that a rule pack loaded from an
// external directory fires alongside the built-in detectors, and that a scan
// without the pack does not raise the custom rule.
func TestExternalRulePackExtendsBuiltins(t *testing.T) {
	dir := filepath.Join("..", "..", "lab", "fixtures", "rulepack")
	s := &surface.Surface{
		Origin: "test",
		Tools:  []mcp.Tool{{Name: "debug_exec", Description: "Run a maintenance task."}},
	}

	// Without the external pack: the custom rule must not fire.
	base, err := NewAnalyzer()
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(base.Surface(s), "CUSTOM.debug-hook") {
		t.Error("custom rule fired without the external pack loaded")
	}

	// With the external pack: the custom rule fires.
	ext, err := NewAnalyzer(dir)
	if err != nil {
		t.Fatalf("load external pack: %v", err)
	}
	if !hasRule(ext.Surface(s), "CUSTOM.debug-hook") {
		t.Error("custom rule did not fire with the external pack loaded")
	}
}

func TestExternalRuleDirErrorIsSurfaced(t *testing.T) {
	if _, err := NewAnalyzer("does-not-exist"); err == nil {
		t.Error("a missing rule directory should be an error, not a silent skip")
	}
}

func hasRule(fs []findings.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}
