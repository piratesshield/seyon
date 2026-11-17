package detect

import (
	"fmt"
	"strings"

	"seyon/internal/findings"
)

// hiddenKind classifies a suspicious rune found in text that an agent reads.
type hiddenKind struct {
	lo, hi rune
	label  string
}

var hiddenRanges = []hiddenKind{
	{0x200B, 0x200D, "zero-width space/joiner"},
	{0x2060, 0x2060, "word joiner"},
	{0xFEFF, 0xFEFF, "zero-width no-break space"},
	{0x202A, 0x202E, "bidirectional override"},
	{0x2066, 0x2069, "bidirectional isolate"},
	{0xE0000, 0xE007F, "unicode tag (invisible instruction)"},
}

// classify returns a label if r is a hidden/invisible or control rune of
// concern, or "" otherwise. Ordinary whitespace (tab, newline, carriage
// return, space) is allowed.
func classify(r rune) string {
	if r == 0x1B {
		return "ANSI escape"
	}
	// C0/C1 control characters other than tab/newline/CR.
	if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || (r >= 0x7F && r <= 0x9F) {
		return "control character"
	}
	for _, h := range hiddenRanges {
		if r >= h.lo && r <= h.hi {
			return h.label
		}
	}
	return ""
}

// scanHidden reports B2 if text contains hidden, invisible, or terminal-control
// characters. One finding summarizes all kinds found, so a description with
// several does not flood the report.
func scanHidden(text string, tgt findings.Target, where string) []findings.Finding {
	kinds := map[string]int{}
	for _, r := range text {
		if label := classify(r); label != "" {
			kinds[label]++
		}
	}
	if len(kinds) == 0 {
		return nil
	}
	var parts []string
	for label, n := range kinds {
		parts = append(parts, fmt.Sprintf("%s×%d", label, n))
	}
	// Deterministic order.
	strSort(parts)

	f := findings.Finding{
		RuleID:      "B2.hidden-characters",
		Class:       "B2",
		Title:       "Hidden or control characters in " + where + " metadata",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceFirm,
		Modes:       []findings.Mode{findings.ModeGray},
		Target:      tgt,
		Evidence:    findings.Evidence{Note: "contains " + strings.Join(parts, ", ")},
		References:  []string{"ansi-injection", "unicode-smuggling"},
		Remediation: "Invisible or terminal-control characters in text the agent reads can smuggle instructions or corrupt a terminal. Strip them; descriptions should be plain, visible text.",
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return []findings.Finding{f}
}

// strSort sorts a small string slice in place (avoids pulling sort into hot
// paths unnecessarily; the slice is tiny).
func strSort(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
