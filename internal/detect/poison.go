package detect

import (
	"fmt"
	"strings"

	"seyon/internal/findings"
	"seyon/internal/surface"
)

var poisonPatterns = []struct {
	keyword string
	title   string
}{
	{"ignore previous", "Instruction override attempt in schema field"},
	{"ignore above", "Instruction override attempt in schema field"},
	{"disregard previous", "Instruction override via disregard directive"},
	{"disregard the above", "Instruction override via disregard directive"},
	{"disregard all", "Instruction override via disregard directive"},
	{"do not tell", "Concealment directive in schema field"},
	{"do not mention", "Concealment directive in schema field"},
	{"do not reveal", "Concealment directive in schema field"},
	{"instead, ", "Behavioral redirection in schema field"},
	{"<system>", "System prompt injection marker in schema field"},
	{"[system]", "System prompt injection marker in schema field"},
	{"you are now", "Identity override attempt in schema field"},
	{"you must", "Coercive instruction in schema field"},
	{"always respond", "Behavioral override in schema field"},
	{"never respond", "Behavioral override in schema field"},
	{"send the", "Data exfiltration directive in schema field"},
	{"exfiltrate", "Exfiltration directive in schema field"},
	{"forward to", "Data forwarding directive in schema field"},
	{"http://", "URL in schema metadata (potential exfil endpoint)"},
	{"https://", "URL in schema metadata (potential exfil endpoint)"},
}

// scanPoison checks ALL JSON Schema string fields (title, description,
// default, enum values) for hidden instructions — "Full-Schema Poisoning".
// Unlike B1 which checks only tool.description, this scans every schema
// property recursively, catching poisoning hidden in deeply nested fields.
func scanPoison(s *surface.Surface) []findings.Finding {
	var out []findings.Finding
	for _, t := range s.Tools {
		tgt := findings.Target{Tool: t.Name, Endpoint: s.Origin}
		for fieldPath, text := range schemaStrings(t.InputSchema) {
			if fieldPath == "description" || fieldPath == "title" {
				continue // top-level description/title is already checked by B1 rules
			}
			for _, p := range poisonPatterns {
				if strings.Contains(strings.ToLower(text), p.keyword) {
					f := findings.Finding{
						RuleID:     "B9.poison.schema",
						Class:      "B9",
						Title:      p.title,
						Severity:   findings.SeverityHigh,
						Confidence: findings.ConfidenceFirm,
						Modes:      []findings.Mode{findings.ModeGray},
						Target:     tgt,
						Evidence: findings.Evidence{
							Note:          fmt.Sprintf("tool %q: hidden instruction found in schema field %q — the keyword %q was detected in a nested schema property that should only describe data shape, not contain directives", tgt.Tool, "schema."+fieldPath, p.keyword),
							SourceSnippet: excerpt(text),
						},
						CWE:         "CWE-74",
						Remediation: "Schema property metadata should describe data shape, not contain instructions. Remove injected content from nested schema fields.",
						StageStatus: findings.StageCompleted,
					}
					f.ID = f.Fingerprint()
					out = append(out, f)
					break // one finding per field
				}
			}
		}
	}
	return out
}
