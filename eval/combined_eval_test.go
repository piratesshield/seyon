package eval_test

import (
	"context"
	"path/filepath"
	"testing"

	"seyon/internal/engine"
	"seyon/internal/findings"
	"seyon/internal/source"
)

// TestCombinedScanRunsBothModes confirms the single-submission orchestration
// runs white-box SAST over the code AND gray-box over a discovered mcp.json in
// the same tree, producing findings from both modes in one report.
func TestCombinedScanRunsBothModes(t *testing.T) {
	dir := filepath.Join("..", "lab", "whitebox", "testdata", "combined")
	resolved, err := source.Local(dir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := engine.CombinedScan(context.Background(), "test", resolved, nil, false)
	if err != nil {
		t.Fatalf("combined scan: %v", err)
	}

	if countClass(r.Findings, "C1") == 0 {
		t.Error("expected a white-box C1 (command injection) finding from handler.go")
	}
	if countClass(r.Findings, "B7") == 0 {
		t.Error("expected a gray-box B7 (risky launch) finding from the discovered mcp.json")
	}

	// Both the sast and gray stages must be recorded (present, not skipped).
	for _, name := range []string{"sast", "gray", "correlate"} {
		if st := stageByName(r, name); st == nil {
			t.Errorf("combined report is missing the %q stage", name)
		}
	}

	// Modes on the report cover both static vantage points.
	modes := map[findings.Mode]bool{}
	for _, m := range r.Modes {
		modes[m] = true
	}
	if !modes[findings.ModeWhite] || !modes[findings.ModeGray] {
		t.Errorf("combined report should declare white+gray modes, got %v", r.Modes)
	}
}
