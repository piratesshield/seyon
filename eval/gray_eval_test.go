package eval_test

import (
	"os"
	"path/filepath"
	"testing"

	"seyon/eval"
	"seyon/internal/baseline"
	"seyon/internal/engine"
	"seyon/internal/surface"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "lab", "fixtures", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// assertPerfect fails unless precision and recall are both 1.0 — every expected
// finding was reported and nothing extra was.
func assertPerfect(t *testing.T, label string, m eval.Metrics) {
	t.Helper()
	if m.Precision != 1.0 || m.Recall != 1.0 {
		t.Errorf("%s: expected perfect precision/recall, got %+v", label, m)
	}
}

func TestGraySurfaceVuln(t *testing.T) {
	r, err := engine.GrayScan("test", readFixture(t, "surface_vuln.json"), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	expected := []eval.Label{
		{Class: "B1", Target: "run_command"},
		{Class: "B6", Target: "run_command"},
		{Class: "B5", Target: "run_command"},
		{Class: "B2", Target: "notes"},
		{Class: "B3", Target: "search"},
		{Class: "B1", Target: "summarize"},
	}
	assertPerfect(t, "surface_vuln", eval.Score(expected, r.Findings))
}

func TestGrayConfigVuln(t *testing.T) {
	r, err := engine.GrayScan("test", readFixture(t, "config_vuln.json"), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	expected := []eval.Label{
		{Class: "B7", Target: "shell-srv"},
		{Class: "B7", Target: "fetch-srv"},
	}
	assertPerfect(t, "config_vuln", eval.Score(expected, r.Findings))
}

func TestGraySafeTwinsHaveNoFindings(t *testing.T) {
	for _, name := range []string{"surface_safe.json", "config_safe.json"} {
		r, err := engine.GrayScan("test", readFixture(t, name), "fixture")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(r.Findings) != 0 {
			t.Errorf("%s: safe twin should yield no findings, got %d: %+v", name, len(r.Findings), r.Findings)
		}
	}
}

func TestDriftDetectsRugPullAndNewTool(t *testing.T) {
	base, err := surface.Parse(readFixture(t, "surface_safe.json"), "baseline")
	if err != nil {
		t.Fatal(err)
	}
	b := baseline.Compute(base)

	r, err := engine.DriftScan("test", b, readFixture(t, "surface_safe_drift.json"), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	expected := []eval.Label{
		{Class: "B4", Target: "echo"},      // description changed → rug-pull
		{Class: "B4", Target: "fetch_url"}, // new tool appeared
	}
	assertPerfect(t, "drift", eval.Score(expected, r.Findings))
	if len(r.Findings) != 2 {
		t.Errorf("expected exactly 2 drift findings, got %d", len(r.Findings))
	}
}
