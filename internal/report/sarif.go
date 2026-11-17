package report

import (
	"encoding/json"
	"io"

	"seyon/internal/findings"
)

// WriteSARIF writes the report as SARIF 2.1.0, so findings drop into code
// scanning UIs and CI. Severity maps to the SARIF level; confidence is carried
// as a property.
func WriteSARIF(w io.Writer, r *Report) error {
	rules := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(r.Findings))

	for _, f := range r.Findings {
		if _, ok := rules[f.RuleID]; !ok {
			props := map[string]interface{}{"class": f.Class}
			if len(f.OWASPIDs) > 0 {
				tags := make([]string, len(f.OWASPIDs))
				for i, o := range f.OWASPIDs {
					tags[i] = string(o)
				}
				props["owasp_mcp_top10"] = tags
			}
			rules[f.RuleID] = sarifRule{
				ID:               f.RuleID,
				Name:             f.Class,
				ShortDescription: sarifText{Text: f.Title},
				Properties:       props,
			}
		}
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Title + " — " + f.Evidence.Note},
			Properties: map[string]interface{}{
				"severity":   string(f.Severity),
				"confidence": string(f.Confidence),
				"class":      f.Class,
				"findingId":  f.ID,
			},
			Locations: sarifLocations(f),
		})
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, f := range r.Findings {
		if rr, ok := rules[f.RuleID]; ok {
			ruleList = append(ruleList, rr)
			delete(rules, f.RuleID)
		}
	}

	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           r.Scanner.Name,
				Version:        r.Scanner.Version,
				InformationURI: "https://example.invalid/seyon",
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifLocations(f findings.Finding) []sarifLocation {
	uri := f.Target.Source
	if uri == "" {
		uri = f.Target.Tool
	}
	if uri == "" {
		uri = f.Target.Endpoint
	}
	if uri == "" {
		return nil
	}
	return []sarifLocation{{
		PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}},
	}}
}

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription sarifText              `json:"shortDescription"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}
type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    sarifText              `json:"message"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Locations  []sarifLocation        `json:"locations,omitempty"`
}
type sarifText struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
