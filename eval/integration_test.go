package eval_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"seyon/eval"
	"seyon/internal/engine"
	"seyon/internal/report"
	"seyon/internal/source"
)

// buildRefServer compiles lab/refserver into a temp binary and returns its path.
func buildRefServer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "refserver")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "seyon/lab/refserver")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build refserver: %v\n%s", err, stderr.String())
	}
	return bin
}

// TestEnumerateAgainstRefServer is the Phase 0 end-to-end check: the scanner
// connects to the reference MCP server over stdio, enumerates the full surface
// across pagination, and produces a well-formed, zero-finding report. This is
// the baseline the eval harness must run green on.
func TestEnumerateAgainstRefServer(t *testing.T) {
	bin := buildRefServer(t)
	spec, err := source.ParseEndpoint("stdio:" + bin)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	r, err := engine.EnumerateReport(ctx, "test", spec)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}

	if r.Inventory == nil {
		t.Fatal("no inventory in report")
	}
	if r.Inventory.Tools != 3 {
		t.Errorf("expected 3 tools (across 2 pages), got %d", r.Inventory.Tools)
	}
	if r.Inventory.Resources != 1 {
		t.Errorf("expected 1 resource, got %d", r.Inventory.Resources)
	}
	if r.Inventory.Prompts != 1 {
		t.Errorf("expected 1 prompt, got %d", r.Inventory.Prompts)
	}
	if !r.Inventory.Complete {
		t.Error("inventory should be complete")
	}
	if r.Inventory.Server != "seyon-refserver" {
		t.Errorf("unexpected server name %q", r.Inventory.Server)
	}
	if len(r.Findings) != 0 {
		t.Errorf("Phase 0 has no detectors; expected 0 findings, got %d", len(r.Findings))
	}

	// The report must serialize to valid JSON.
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, r); err != nil {
		t.Fatalf("write json: %v", err)
	}
	var back report.Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("report json does not round-trip: %v", err)
	}

	// With no expected labels and no findings, eval is a perfect negative.
	m := eval.Score(nil, r.Findings)
	if m.Precision != 1.0 || m.Recall != 1.0 {
		t.Errorf("baseline eval not perfect: %+v", m)
	}
}

// TestEnumerateBadEndpoint confirms a connect failure is reported as a stage
// error, not a clean scan.
func TestEnumerateBadEndpoint(t *testing.T) {
	spec, err := source.ParseEndpoint("stdio:/nonexistent/seyon-xyz")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r, err := engine.EnumerateReport(ctx, "test", spec)
	if err == nil {
		t.Fatal("expected an error for a nonexistent command")
	}
	// The report should record a non-clean stage.
	foundErr := false
	for _, s := range r.Stages {
		if s.Status == "error" {
			foundErr = true
		}
	}
	if !foundErr {
		t.Error("expected an error stage in the report")
	}
}
