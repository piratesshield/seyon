package eval_test

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"seyon/internal/engine"
	"seyon/internal/findings"
	"seyon/internal/report"
	"seyon/internal/scope"
	"seyon/internal/source"
)

// stageByName returns the named stage from a report, or nil.
func stageByName(r *report.Report, name string) *report.Stage {
	for i := range r.Stages {
		if r.Stages[i].Name == name {
			return &r.Stages[i]
		}
	}
	return nil
}

// buildProbeServer compiles lab/probesrv into a temp binary and returns its path.
func buildProbeServer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "probesrv")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "seyon/lab/probesrv")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build probesrv: %v\n%s", err, stderr.String())
	}
	return bin
}

func countClass(fs []findings.Finding, class string) int {
	n := 0
	for _, f := range fs {
		if f.Class == class {
			n++
		}
	}
	return n
}

// TestBlackPassiveDoesNotProbe confirms the safe-by-default posture: without
// --active, the scan connects and enumerates but records the active-probe stage
// as skipped and invokes no tools.
func TestBlackPassiveDoesNotProbe(t *testing.T) {
	bin := buildProbeServer(t)
	spec, err := source.ParseEndpoint("stdio:" + bin)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	r, err := engine.BlackScan(ctx, "test", spec, engine.BlackOptions{})
	if err != nil {
		t.Fatalf("black passive scan: %v", err)
	}
	if r.Inventory == nil || r.Inventory.Tools != 4 {
		t.Fatalf("expected 4 enumerated tools, got %+v", r.Inventory)
	}
	if countClass(r.Findings, "E") != 0 {
		t.Errorf("passive scan must not produce runtime (E) findings, got %d", countClass(r.Findings, "E"))
	}
	st := stageByName(r, "active-probe")
	if st == nil || st.Status != findings.StageSkipped {
		t.Errorf("expected active-probe stage skipped, got %+v", st)
	}
}

// TestBlackActiveConfirmsReflection confirms the active prober runtime-confirms
// an E reflection finding on each reflecting tool (echo, poison) and produces
// nothing for classify (string input, not reflected) or add (no string input).
func TestBlackActiveConfirmsReflection(t *testing.T) {
	bin := buildProbeServer(t)
	raw := "stdio:" + bin
	spec, err := source.ParseEndpoint(raw)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Egress denial off keeps the test independent of unshare availability; the
	// probe server needs no network. The authorization gate is still exercised.
	egressOff := false
	sc := &scope.Scope{AllowActive: true, Targets: []string{raw}, DenyEgress: &egressOff}

	r, err := engine.BlackScan(ctx, "test", spec, engine.BlackOptions{Active: true, Scope: sc})
	if err != nil {
		t.Fatalf("black active scan: %v", err)
	}

	reflected := map[string]bool{}
	for _, f := range r.Findings {
		if f.Class == "E" {
			if f.Confidence != findings.ConfidenceConfirmed {
				t.Errorf("runtime reflection must be confirmed confidence, got %q on %q", f.Confidence, f.Target.Tool)
			}
			reflected[f.Target.Tool] = true
		}
	}
	if !reflected["echo"] || !reflected["poison"] {
		t.Errorf("expected E findings on echo and poison, got %v", reflected)
	}
	if reflected["classify"] || reflected["add"] {
		t.Errorf("non-reflecting tools must not produce E findings, got %v", reflected)
	}
	st := stageByName(r, "active-probe")
	if st == nil || st.Status == findings.StageSkipped {
		t.Errorf("active-probe stage should have run, got %+v", st)
	}
}

// TestBlackActiveCorrelatesAcrossModes confirms that the poison tool — which has
// a tool-poisoning description (gray B1) and reflects input at runtime (black E)
// — yields exactly one cross-mode correlation (class X) tying the two together,
// with the elevated severity/confidence and both members referenced.
func TestBlackActiveCorrelatesAcrossModes(t *testing.T) {
	bin := buildProbeServer(t)
	raw := "stdio:" + bin
	spec, err := source.ParseEndpoint(raw)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	egressOff := false
	sc := &scope.Scope{AllowActive: true, Targets: []string{raw}, DenyEgress: &egressOff}
	r, err := engine.BlackScan(ctx, "test", spec, engine.BlackOptions{Active: true, Scope: sc})
	if err != nil {
		t.Fatalf("black active scan: %v", err)
	}

	var x []findings.Finding
	for _, f := range r.Findings {
		if f.Class == "X" {
			x = append(x, f)
		}
	}
	if len(x) != 1 {
		t.Fatalf("expected exactly 1 cross-mode correlation, got %d: %+v", len(x), x)
	}
	c := x[0]
	if c.Target.Tool != "poison" {
		t.Errorf("correlation should be on tool 'poison', got %q", c.Target.Tool)
	}
	if c.Confidence != findings.ConfidenceConfirmed {
		t.Errorf("correlation confidence should be elevated to confirmed, got %q", c.Confidence)
	}
	if c.Severity != findings.SeverityHigh {
		t.Errorf("correlation severity should be elevated to high, got %q", c.Severity)
	}
	if len(c.Related) != 2 {
		t.Errorf("correlation should reference its 2 member findings, got %v", c.Related)
	}
}

// TestBlackActiveRefusesUnscopedTarget confirms a scope that does not list the
// target leaves the active-probe stage skipped and invokes nothing.
func TestBlackActiveRefusesUnscopedTarget(t *testing.T) {
	bin := buildProbeServer(t)
	spec, err := source.ParseEndpoint("stdio:" + bin)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	egressOff := false
	sc := &scope.Scope{AllowActive: true, Targets: []string{"stdio:some-other-target"}, DenyEgress: &egressOff}

	r, err := engine.BlackScan(ctx, "test", spec, engine.BlackOptions{Active: true, Scope: sc})
	if err != nil {
		t.Fatalf("black scan: %v", err)
	}
	if countClass(r.Findings, "E") != 0 {
		t.Errorf("unscoped target must not be probed, got %d E findings", countClass(r.Findings, "E"))
	}
	st := stageByName(r, "active-probe")
	if st == nil || st.Status != findings.StageSkipped {
		t.Errorf("expected active-probe skipped for unscoped target, got %+v", st)
	}
}
