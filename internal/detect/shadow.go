package detect

import (
	"fmt"
	"strings"

	"seyon/internal/findings"
	"seyon/internal/surface"
)

// scanShadowing reports B3 when two tools in the same surface share a name, or
// share a name differing only by case. A collision lets one definition shadow
// another, so the agent may invoke a different tool than intended.
func scanShadowing(s *surface.Surface) []findings.Finding {
	byLower := map[string][]string{} // lower name -> exact names seen
	order := []string{}              // preserve first-seen lower names
	for _, t := range s.Tools {
		lo := strings.ToLower(t.Name)
		if _, ok := byLower[lo]; !ok {
			order = append(order, lo)
		}
		byLower[lo] = append(byLower[lo], t.Name)
	}

	var out []findings.Finding
	for _, lo := range order {
		names := byLower[lo]
		if len(names) < 2 {
			continue
		}
		exactDup := countExactDuplicate(names)
		title := "Tool name collides across definitions (case-insensitive)"
		sev := findings.SeverityMedium
		if exactDup {
			title = "Duplicate tool name in the same surface"
			sev = findings.SeverityMedium
		}
		f := findings.Finding{
			RuleID:      "B3.tool-shadowing",
			Class:       "B3",
			Title:       title,
			Severity:    sev,
			Confidence:  findings.ConfidenceFirm,
			Modes:       []findings.Mode{findings.ModeGray},
			Target:      findings.Target{Tool: names[0], Endpoint: s.Origin},
			Evidence:    findings.Evidence{Note: fmt.Sprintf("names: %s", strings.Join(names, ", "))},
			References:  []string{"tool-shadowing"},
			Remediation: "Give every tool a unique, case-distinct name. A collision lets one tool definition shadow another and mislead the agent.",
			StageStatus: findings.StageCompleted,
		}
		f.ID = f.Fingerprint()
		out = append(out, f)
	}
	return out
}

func countExactDuplicate(names []string) bool {
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			return true
		}
		seen[n] = true
	}
	return false
}
