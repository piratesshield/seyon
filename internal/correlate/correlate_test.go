package correlate

import "testing"

import "seyon/internal/findings"

func mk(class string, mode findings.Mode, tool string, sev findings.Severity, conf findings.Confidence) findings.Finding {
	f := findings.Finding{
		RuleID: class + ".r", Class: class, Title: class, Severity: sev, Confidence: conf,
		Modes: []findings.Mode{mode}, Target: findings.Target{Tool: tool},
		Evidence: findings.Evidence{Note: "x"}, StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return f
}

func TestCorrelatesCrossModeSameFamilyAndTool(t *testing.T) {
	in := []findings.Finding{
		mk("B1", findings.ModeGray, "echo", findings.SeverityHigh, findings.ConfidenceTentative),
		mk("E", findings.ModeBlack, "echo", findings.SeverityMedium, findings.ConfidenceConfirmed),
	}
	out := Findings(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 correlation, got %d", len(out))
	}
	c := out[0]
	if c.Class != "X" || c.Target.Tool != "echo" {
		t.Errorf("unexpected correlation %+v", c)
	}
	if c.Severity != findings.SeverityHigh {
		t.Errorf("severity should be max (high), got %q", c.Severity)
	}
	if c.Confidence != findings.ConfidenceConfirmed {
		t.Errorf("confidence should be max (confirmed), got %q", c.Confidence)
	}
	if len(c.Related) != 2 {
		t.Errorf("should reference 2 members, got %v", c.Related)
	}
}

func TestNoCorrelationWithinOneMode(t *testing.T) {
	in := []findings.Finding{
		mk("B1", findings.ModeGray, "echo", findings.SeverityHigh, findings.ConfidenceTentative),
		mk("B2", findings.ModeGray, "echo", findings.SeverityHigh, findings.ConfidenceTentative),
	}
	if out := Findings(in); len(out) != 0 {
		t.Errorf("single-mode group must not correlate, got %d", len(out))
	}
}

func TestNoCorrelationAcrossDifferentTools(t *testing.T) {
	in := []findings.Finding{
		mk("B1", findings.ModeGray, "echo", findings.SeverityHigh, findings.ConfidenceTentative),
		mk("E", findings.ModeBlack, "other", findings.SeverityMedium, findings.ConfidenceConfirmed),
	}
	if out := Findings(in); len(out) != 0 {
		t.Errorf("different tools must not correlate, got %d", len(out))
	}
}

func TestNoCorrelationAcrossDifferentFamilies(t *testing.T) {
	in := []findings.Finding{
		mk("C3", findings.ModeWhite, "echo", findings.SeverityHigh, findings.ConfidenceFirm),       // ssrf
		mk("E", findings.ModeBlack, "echo", findings.SeverityMedium, findings.ConfidenceConfirmed), // injection
	}
	if out := Findings(in); len(out) != 0 {
		t.Errorf("different families must not correlate, got %d", len(out))
	}
}

func TestUncorrelatableClassIgnored(t *testing.T) {
	in := []findings.Finding{
		mk("B5", findings.ModeGray, "echo", findings.SeverityLow, findings.ConfidenceTentative),
		mk("B5", findings.ModeBlack, "echo", findings.SeverityLow, findings.ConfidenceTentative),
	}
	if out := Findings(in); len(out) != 0 {
		t.Errorf("classes with no family must not correlate, got %d", len(out))
	}
}
