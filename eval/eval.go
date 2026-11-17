// Package eval scores a scan against ground-truth labels. It is how every later
// phase is measured for precision and recall on the vulnerable-twin lab, so a
// detector's coverage is a number, not a claim.
package eval

import "seyon/internal/findings"

// Label is one ground-truth positive: a finding that should be reported, keyed
// by class and the target it applies to.
type Label struct {
	Class  string
	Target string // tool name or source location
}

// Metrics holds the outcome of scoring.
type Metrics struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
}

// key normalizes a finding or label to its (class, target) identity.
func targetKey(class, target string) string { return class + "\x00" + target }

func findingKey(f findings.Finding) string {
	t := f.Target.Tool
	if t == "" {
		t = f.Target.Source
	}
	if t == "" {
		t = f.Target.Resource
	}
	return targetKey(f.Class, t)
}

// Score compares reported findings against expected labels, matching on
// (class, target). With no expected labels and no reported findings, precision
// and recall are 1.0 by convention (a perfect negative result).
func Score(expected []Label, got []findings.Finding) Metrics {
	want := make(map[string]bool, len(expected))
	for _, l := range expected {
		want[targetKey(l.Class, l.Target)] = true
	}
	seen := make(map[string]bool, len(got))

	var m Metrics
	for _, f := range got {
		k := findingKey(f)
		if seen[k] {
			continue // count each matched identity once
		}
		seen[k] = true
		if want[k] {
			m.TP++
		} else {
			m.FP++
		}
	}
	for k := range want {
		if !seen[k] {
			m.FN++
		}
	}

	if m.TP+m.FP == 0 {
		m.Precision = 1.0
	} else {
		m.Precision = float64(m.TP) / float64(m.TP+m.FP)
	}
	if m.TP+m.FN == 0 {
		m.Recall = 1.0
	} else {
		m.Recall = float64(m.TP) / float64(m.TP+m.FN)
	}
	return m
}
