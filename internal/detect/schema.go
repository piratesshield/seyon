package detect

import (
	"encoding/json"
	"fmt"
	"strings"

	"seyon/internal/findings"
	"seyon/internal/mcp"
)

// jsonSchema is a loose view of the subset of JSON Schema Seyon inspects.
type jsonSchema struct {
	Type       string                `json:"type"`
	Properties map[string]jsonSchema `json:"properties"`
	Items      *jsonSchema           `json:"items"`
	Enum       []json.RawMessage     `json:"enum"`
	Format     string                `json:"format"`
	MaxLength  *int                  `json:"maxLength"`
	MaxItems   *int                  `json:"maxItems"`
	Pattern    string                `json:"pattern"`
}

// scanSchema reports B5 when a tool's input schema leaves parameters
// unconstrained: a string with no maxLength/enum/pattern/format, or an array
// with no maxItems. A tool that declares no input schema is not flagged (it may
// legitimately take no arguments); only a declared-but-loose schema is.
func scanSchema(t mcp.Tool, origin string) []findings.Finding {
	if len(t.InputSchema) == 0 {
		return nil
	}
	var s jsonSchema
	if err := json.Unmarshal(t.InputSchema, &s); err != nil {
		return nil // not a schema shape we understand; don't guess
	}
	if len(s.Properties) == 0 {
		return nil
	}
	var weak []string
	for name, p := range s.Properties {
		if reason := weakProp(p); reason != "" {
			weak = append(weak, fmt.Sprintf("%s (%s)", name, reason))
		}
	}
	if len(weak) == 0 {
		return nil
	}
	strSort(weak)
	f := findings.Finding{
		RuleID:     "B5.weak-schema",
		Class:      "B5",
		Title:      "Tool input schema leaves parameters unconstrained",
		Severity:   findings.SeverityLow,
		Confidence: findings.ConfidenceTentative,
		Modes:      []findings.Mode{findings.ModeGray},
		Target:     findings.Target{Tool: t.Name, Endpoint: origin},
		Evidence: findings.Evidence{
			Note: fmt.Sprintf("tool %q declares %d unconstrained parameter(s): %s — an attacker can send arbitrarily large or shaped input to these fields", t.Name, len(weak), strings.Join(weak, "; ")),
		},
		References:  []string{"weak-schema"},
		Remediation: "Constrain parameters that reach sensitive sinks: add maxLength/pattern/enum to strings and maxItems to arrays, so a handler cannot be fed arbitrarily large or shaped input.",
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return []findings.Finding{f}
}

func weakProp(p jsonSchema) string {
	switch p.Type {
	case "string":
		if p.MaxLength == nil && len(p.Enum) == 0 && p.Format == "" && p.Pattern == "" {
			return "string with no maxLength/enum/pattern/format"
		}
	case "array":
		if p.MaxItems == nil {
			return "array with no maxItems"
		}
	case "":
		if len(p.Enum) == 0 {
			return "no declared type"
		}
	}
	return ""
}
