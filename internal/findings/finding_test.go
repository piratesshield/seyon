package findings

import "testing"

func validFinding() Finding {
	return Finding{
		Class:       "C1",
		Title:       "shell injection",
		Severity:    SeverityCritical,
		Confidence:  ConfidenceConfirmed,
		Target:      Target{Tool: "run", Source: "exec.go:42"},
		Evidence:    Evidence{Canary: "marker"},
		StageStatus: StageCompleted,
	}
}

func TestValidate(t *testing.T) {
	if err := validFinding().Validate(); err != nil {
		t.Fatalf("valid finding rejected: %v", err)
	}
	cases := map[string]func(*Finding){
		"no class":       func(f *Finding) { f.Class = "" },
		"no title":       func(f *Finding) { f.Title = "" },
		"bad severity":   func(f *Finding) { f.Severity = "nope" },
		"bad confidence": func(f *Finding) { f.Confidence = "nope" },
		"no stage":       func(f *Finding) { f.StageStatus = "" },
		"no evidence":    func(f *Finding) { f.Evidence = Evidence{} },
	}
	for name, mut := range cases {
		f := validFinding()
		mut(&f)
		if err := f.Validate(); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestFingerprintStableAndDistinct(t *testing.T) {
	a := validFinding()
	b := validFinding()
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("same inputs produced different fingerprints")
	}
	// Evidence text must not affect the fingerprint.
	b.Evidence.Canary = "different marker"
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("evidence changed the fingerprint; it should not")
	}
	// A different target must change it.
	c := validFinding()
	c.Target.Source = "other.go:1"
	if a.Fingerprint() == c.Fingerprint() {
		t.Error("different target produced the same fingerprint")
	}
}

func TestDedupUnionsModes(t *testing.T) {
	a := validFinding()
	a.Modes = []Mode{ModeWhite}
	b := validFinding()
	b.Modes = []Mode{ModeBlack}
	out := Dedup([]Finding{a, b})
	if len(out) != 1 {
		t.Fatalf("expected 1 finding after dedup, got %d", len(out))
	}
	if len(out[0].Modes) != 2 {
		t.Errorf("expected modes to union to 2, got %v", out[0].Modes)
	}
}

func TestSortMostSevereFirst(t *testing.T) {
	fs := []Finding{
		{Severity: SeverityLow, Confidence: ConfidenceFirm, ID: "b"},
		{Severity: SeverityCritical, Confidence: ConfidenceTentative, ID: "a"},
		{Severity: SeverityCritical, Confidence: ConfidenceConfirmed, ID: "c"},
	}
	Sort(fs)
	if fs[0].ID != "c" || fs[1].ID != "a" || fs[2].ID != "b" {
		t.Errorf("unexpected order: %s %s %s", fs[0].ID, fs[1].ID, fs[2].ID)
	}
}
