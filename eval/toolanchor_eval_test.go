package eval_test

import (
	"context"
	"path/filepath"
	"testing"

	"seyon/internal/engine"
	"seyon/internal/findings"
	"seyon/internal/source"
)

// TestToolAnchoredCorrelation proves the v1.5 capability end-to-end: a
// white-box C1 sink in a registered tool handler and a gray-box B1 poisoning on
// the same tool's declared surface are anchored to the same tool name, so
// cross-mode correlation produces a class-X finding tying them together.
func TestToolAnchoredCorrelation(t *testing.T) {
	dir := filepath.Join("..", "lab", "whitebox", "testdata", "toolcorrelate")
	resolved, err := source.Local(dir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := engine.CombinedScan(context.Background(), "test", resolved, nil, false)
	if err != nil {
		t.Fatalf("combined scan: %v", err)
	}

	// White-box C1 anchored to the tool.
	c1 := findByClassTool(r.Findings, "C1", "run_command")
	if c1 == nil {
		t.Fatalf("expected a white-box C1 anchored to tool run_command; findings: %s", dump(r.Findings))
	}
	if !hasMode(c1, findings.ModeWhite) {
		t.Errorf("C1 should be a white-box finding, modes = %v", c1.Modes)
	}

	// Gray-box B1 on the same tool.
	b1 := findByClassTool(r.Findings, "B1", "run_command")
	if b1 == nil {
		t.Fatalf("expected a gray-box B1 on tool run_command; findings: %s", dump(r.Findings))
	}

	// Cross-mode correlation: a class-X finding on run_command referencing both.
	x := findByClassTool(r.Findings, "X", "run_command")
	if x == nil {
		t.Fatalf("expected a class-X correlation on tool run_command; findings: %s", dump(r.Findings))
	}
	if len(x.Modes) < 2 {
		t.Errorf("X finding should span >1 mode, got %v", x.Modes)
	}
	related := map[string]bool{}
	for _, id := range x.Related {
		related[id] = true
	}
	if !related[c1.ID] {
		t.Errorf("X finding should reference the white-box C1 (%s); related = %v", c1.ID, x.Related)
	}
	if !related[b1.ID] {
		t.Errorf("X finding should reference the gray-box B1 (%s); related = %v", b1.ID, x.Related)
	}
}

func findByClassTool(fs []findings.Finding, class, tool string) *findings.Finding {
	for i := range fs {
		if fs[i].Class == class && fs[i].Target.Tool == tool {
			return &fs[i]
		}
	}
	return nil
}

func hasMode(f *findings.Finding, m findings.Mode) bool {
	for _, x := range f.Modes {
		if x == m {
			return true
		}
	}
	return false
}

func dump(fs []findings.Finding) string {
	out := ""
	for _, f := range fs {
		out += "\n  " + f.Class + " tool=" + f.Target.Tool + " src=" + f.Target.Source
	}
	return out
}
