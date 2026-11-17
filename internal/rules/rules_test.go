package rules

import "testing"

const sample = `
rules:
  - id: T1.sub
    class: B1
    severity: high
    confidence: tentative
    title: substring rule
    match:
      field: tool.description
      any_substring: ["ignore previous", "Secret Phrase"]
  - id: T2.rx
    class: B6
    severity: low
    confidence: tentative
    title: regex rule
    match:
      field: tool.name
      any_regex: ["(?i)^exec$"]
`

func TestLoadAndHit(t *testing.T) {
	rs, err := Load([]byte(sample))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rs.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rs.Rules))
	}

	desc := rs.ForField(FieldToolDesc)
	if len(desc) != 1 {
		t.Fatalf("expected 1 description rule, got %d", len(desc))
	}
	// Substring match is case-insensitive.
	if !desc[0].Hit("Please IGNORE PREVIOUS directives") {
		t.Error("case-insensitive substring did not match")
	}
	if desc[0].Hit("totally benign text") {
		t.Error("unexpected substring match")
	}

	name := rs.ForField(FieldToolName)
	if !name[0].Hit("EXEC") {
		t.Error("case-insensitive regex did not match")
	}
	if name[0].Hit("execute") {
		t.Error("anchored regex should not match 'execute'")
	}
}

func TestLoadValidation(t *testing.T) {
	cases := map[string]string{
		"bad severity": `rules: [{id: x, class: B1, severity: nope, confidence: firm, title: t, match: {field: tool.name, any_substring: [a]}}]`,
		"bad field":    `rules: [{id: x, class: B1, severity: high, confidence: firm, title: t, match: {field: bogus, any_substring: [a]}}]`,
		"no patterns":  `rules: [{id: x, class: B1, severity: high, confidence: firm, title: t, match: {field: tool.name}}]`,
		"bad regex":    `rules: [{id: x, class: B1, severity: high, confidence: firm, title: t, match: {field: tool.name, any_regex: ["("]}}]`,
		"dup id":       `rules: [{id: x, class: B1, severity: high, confidence: firm, title: t, match: {field: tool.name, any_substring: [a]}}, {id: x, class: B1, severity: high, confidence: firm, title: t2, match: {field: tool.name, any_substring: [b]}}]`,
	}
	for name, src := range cases {
		if _, err := Load([]byte(src)); err == nil {
			t.Errorf("%s: expected load error, got nil", name)
		}
	}
}
