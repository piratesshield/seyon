package eval_test

import (
	"testing"

	"seyon/eval"
	"seyon/internal/engine"
)

// TestScorecard is Seyon's evaluation harness: it runs the labeled vulnerable
// and safe twin corpora through the engine, aggregates precision/recall, and
// prints a scorecard. It fails if accuracy on the labeled gray-box corpora
// regresses below perfect — the bar the detectors are held to.
func TestScorecard(t *testing.T) {
	type corpus struct {
		name     string
		fixture  string
		expected []eval.Label
	}
	corpora := []corpus{
		{"gray/surface_vuln", "surface_vuln.json", []eval.Label{
			{Class: "B1", Target: "run_command"},
			{Class: "B6", Target: "run_command"},
			{Class: "B5", Target: "run_command"},
			{Class: "B2", Target: "notes"},
			{Class: "B3", Target: "search"},
			{Class: "B1", Target: "summarize"},
		}},
		{"gray/config_vuln", "config_vuln.json", []eval.Label{
			{Class: "B7", Target: "shell-srv"},
			{Class: "B7", Target: "fetch-srv"},
		}},
		{"gray/surface_safe", "surface_safe.json", nil},
		{"gray/config_safe", "config_safe.json", nil},
	}

	var agg eval.Metrics
	t.Log("Seyon evaluation scorecard")
	t.Log("corpus                  TP  FP  FN   precision  recall")
	for _, c := range corpora {
		r, err := engine.GrayScan("test", readFixture(t, c.fixture), "fixture")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		m := eval.Score(c.expected, r.Findings)
		agg.TP += m.TP
		agg.FP += m.FP
		agg.FN += m.FN
		t.Logf("%-22s %3d %3d %3d   %7.2f  %6.2f", c.name, m.TP, m.FP, m.FN, m.Precision, m.Recall)
	}

	prec, rec := ratio(agg.TP, agg.FP), ratio(agg.TP, agg.FN)
	t.Logf("%-22s %3d %3d %3d   %7.2f  %6.2f", "AGGREGATE", agg.TP, agg.FP, agg.FN, prec, rec)

	if prec != 1.0 || rec != 1.0 {
		t.Errorf("gray-box corpora regressed: precision=%.2f recall=%.2f (want 1.00/1.00)", prec, rec)
	}
	if agg.TP == 0 {
		t.Error("scorecard found no true positives; the harness is not exercising the detectors")
	}
}

// ratio is tp/(tp+other) with the 0/0 == 1.0 convention used by eval.Score.
func ratio(tp, other int) float64 {
	if tp+other == 0 {
		return 1.0
	}
	return float64(tp) / float64(tp+other)
}
