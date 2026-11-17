// Package correlate ties together findings that describe the same underlying
// weakness on the same target seen from different vantage points. A static sink
// (white-box), a poisoned declaration (gray-box), and a runtime observation
// (black-box) about one tool are, together, stronger evidence than any one
// alone. Correlation never deletes a member finding; it adds a class "X"
// finding that references the members and carries the elevated assessment, so
// the underlying evidence stays auditable.
package correlate

import (
	"sort"
	"strings"

	"seyon/internal/findings"
)

// family groups finding classes that are facets of the same weakness. Only
// findings in the same family and on the same target tool can correlate.
var family = map[string]string{
	"B1": "injection", // tool/prompt poisoning (declared)
	"E":  "injection", // runtime input→output reflection
	"C1": "injection", // command injection (static sink)
	"B2": "injection", // hidden-character payloads
	"C3": "ssrf",
	"C2": "traversal",
	"C4": "sqli",
	"C5": "secrets",
	"B6": "authz",
	"C6": "authz",
	"D1": "supply-chain",
	"D2": "supply-chain",
	"D3": "supply-chain",
}

// familyOf returns the weakness family for a class, or "" if the class does not
// participate in correlation.
func familyOf(class string) string { return family[class] }

// familyTitle is a human label per family.
var familyTitle = map[string]string{
	"injection":    "Injection surface corroborated across modes",
	"ssrf":         "Server-side request forgery corroborated across modes",
	"traversal":    "Path traversal corroborated across modes",
	"sqli":         "SQL injection corroborated across modes",
	"secrets":      "Secret exposure corroborated across modes",
	"authz":        "Missing authorization corroborated across modes",
	"supply-chain": "Supply-chain risk corroborated across modes",
}

// Findings returns the correlated (class "X") findings for a set of findings.
// A group correlates only when, for one (family, tool), the members span more
// than one scanning mode — that cross-mode agreement is the added signal. The
// returned findings are new; the inputs are not modified.
func Findings(fs []findings.Finding) []findings.Finding {
	type group struct {
		members []findings.Finding
		modes   map[findings.Mode]bool
	}
	groups := map[string]*group{}

	for _, f := range fs {
		fam := familyOf(f.Class)
		tool := f.Target.Tool
		if fam == "" || tool == "" {
			continue // only tool-anchored, correlatable classes participate
		}
		key := fam + "\x00" + tool
		g := groups[key]
		if g == nil {
			g = &group{modes: map[findings.Mode]bool{}}
			groups[key] = g
		}
		g.members = append(g.members, f)
		for _, m := range f.Modes {
			g.modes[m] = true
		}
	}

	var out []findings.Finding
	for key, g := range groups {
		if len(g.modes) < 2 {
			continue // single-mode: no cross-mode corroboration to add
		}
		fam := strings.SplitN(key, "\x00", 2)[0]
		tool := strings.SplitN(key, "\x00", 2)[1]
		out = append(out, correlated(fam, tool, g.members, g.modes))
	}
	findings.Sort(out)
	return out
}

func correlated(fam, tool string, members []findings.Finding, modeSet map[findings.Mode]bool) findings.Finding {
	// Elevated assessment: take the strongest severity and confidence seen among
	// the corroborating members — agreement raises our certainty.
	var sev findings.Severity
	var conf findings.Confidence
	ids := make([]string, 0, len(members))
	classes := map[string]bool{}
	for _, m := range members {
		if severityRank(m.Severity) > severityRank(sev) {
			sev = m.Severity
		}
		if confidenceRank(m.Confidence) > confidenceRank(conf) {
			conf = m.Confidence
		}
		ids = append(ids, m.ID)
		classes[m.Class] = true
	}
	sort.Strings(ids)

	modes := make([]findings.Mode, 0, len(modeSet))
	for m := range modeSet {
		modes = append(modes, m)
	}
	sort.Slice(modes, func(i, j int) bool { return modes[i] < modes[j] })

	title := familyTitle[fam]
	if title == "" {
		title = "Weakness corroborated across modes"
	}
	f := findings.Finding{
		RuleID:     "X." + fam,
		Class:      "X",
		Title:      title,
		Severity:   sev,
		Confidence: conf,
		Modes:      modes,
		Target:     findings.Target{Tool: tool},
		Evidence: findings.Evidence{
			Note: "tool " + tool + ": " + strings.Join(sortedKeys(classes), "+") +
				" findings agree across " + modeNames(modes) + " — treat as corroborated",
		},
		References:  []string{"cross-mode-correlation"},
		Remediation: "Prioritize remediation: this weakness is evidenced from more than one vantage point. Start from the member findings referenced here.",
		StageStatus: findings.StageCompleted,
		Related:     ids,
	}
	f.ID = f.Fingerprint()
	return f
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func modeNames(modes []findings.Mode) string {
	parts := make([]string, len(modes))
	for i, m := range modes {
		parts[i] = string(m)
	}
	return strings.Join(parts, "/")
}

// severityRank / confidenceRank mirror the ordering in the findings package
// (whose own ranks are unexported) for the max-wins elevation.
func severityRank(s findings.Severity) int {
	switch s {
	case findings.SeverityCritical:
		return 5
	case findings.SeverityHigh:
		return 4
	case findings.SeverityMedium:
		return 3
	case findings.SeverityLow:
		return 2
	case findings.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func confidenceRank(c findings.Confidence) int {
	switch c {
	case findings.ConfidenceConfirmed:
		return 3
	case findings.ConfidenceFirm:
		return 2
	case findings.ConfidenceTentative:
		return 1
	default:
		return 0
	}
}
