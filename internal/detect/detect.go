// Package detect holds Seyon's gray-box detectors: the B-family checks over a
// server's declared surface and client configuration. Pattern-based checks
// (B1, B6, B7) are driven by embedded YAML rule packs; structural checks (B2
// hidden characters, B3 shadowing, B5 weak schema) are code.
package detect

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"seyon/internal/findings"
	"seyon/internal/manifest"
	"seyon/internal/rules"
	"seyon/internal/surface"
	"seyon/internal/threatdb"
)

//go:embed rules_builtin/*.yaml
var builtinFS embed.FS

// Analyzer runs the gray-box detectors. It is safe for concurrent use.
type Analyzer struct {
	rules *rules.RuleSet
}

// NewAnalyzer loads the embedded rule packs plus any external rule-pack
// directories given (each is scanned for *.yaml / *.yml files). External packs
// extend the built-in detectors, so a team can ship its own rules without
// recompiling. A directory that cannot be read, or a pack that fails to parse,
// is an error rather than a silent skip.
func NewAnalyzer(extraDirs ...string) (*Analyzer, error) {
	rs, err := loadBuiltinRules()
	if err != nil {
		return nil, err
	}
	for _, dir := range extraDirs {
		if dir == "" {
			continue
		}
		extra, err := loadRuleDir(dir)
		if err != nil {
			return nil, err
		}
		rs.Rules = append(rs.Rules, extra.Rules...)
	}
	return &Analyzer{rules: rs}, nil
}

// loadRuleDir loads every *.yaml/*.yml rule pack in a directory.
func loadRuleDir(dir string) (*rules.RuleSet, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("detect: read rule dir %q: %w", dir, err)
	}
	merged := &rules.RuleSet{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("detect: read rule pack %q: %w", e.Name(), err)
		}
		rs, err := rules.Load(b)
		if err != nil {
			return nil, fmt.Errorf("detect: load %s: %w", e.Name(), err)
		}
		merged.Rules = append(merged.Rules, rs.Rules...)
	}
	return merged, nil
}

// RuleCount reports how many rules are loaded (for diagnostics).
func (a *Analyzer) RuleCount() int { return len(a.rules.Rules) }

func loadBuiltinRules() (*rules.RuleSet, error) {
	merged := &rules.RuleSet{}
	entries, err := fs.ReadDir(builtinFS, "rules_builtin")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		b, err := builtinFS.ReadFile("rules_builtin/" + e.Name())
		if err != nil {
			return nil, err
		}
		rs, err := rules.Load(b)
		if err != nil {
			return nil, fmt.Errorf("detect: load %s: %w", e.Name(), err)
		}
		merged.Rules = append(merged.Rules, rs.Rules...)
	}
	return merged, nil
}

func fromRule(r rules.Rule, tgt findings.Target, field, value string) findings.Finding {
	f := findings.Finding{
		RuleID:     r.ID,
		Class:      r.Class,
		Title:      r.Title,
		Severity:   findings.Severity(r.Severity),
		Confidence: findings.Confidence(r.Confidence),
		Modes:      []findings.Mode{findings.ModeGray},
		Target:     tgt,
		Evidence: findings.Evidence{
			Note:          fmt.Sprintf("matched rule %s on %s — pattern found in %s of tool %q", r.ID, field, field, tgt.Tool),
			SourceSnippet: excerpt(value),
		},
		CWE:         r.CWE,
		References:  r.References,
		Remediation: r.Remediation,
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return f
}

// excerpt trims a value for evidence display.
func excerpt(s string) string {
	s = strings.TrimSpace(s)
	const maxLen = 160
	if len(s) > maxLen {
		return s[:maxLen] + "…"
	}
	return s
}

// Surface runs the surface detectors (B1, B2, B3, B5, B6) over a declared
// capability surface.
func (a *Analyzer) Surface(s *surface.Surface) []findings.Finding {
	var out []findings.Finding

	nameRules := a.rules.ForField(rules.FieldToolName)
	descRules := a.rules.ForField(rules.FieldToolDesc)
	promptRules := a.rules.ForField(rules.FieldPromptDesc)

	for _, t := range s.Tools {
		tgt := findings.Target{Tool: t.Name, Endpoint: s.Origin}
		for _, r := range nameRules {
			if r.Hit(t.Name) {
				out = append(out, fromRule(r, tgt, "tool.name", t.Name))
			}
		}
		for _, r := range descRules {
			if r.Hit(t.Description) {
				out = append(out, fromRule(r, tgt, "tool.description", t.Description))
			}
		}
		out = append(out, scanHidden(t.Name+"\n"+t.Description, tgt, "tool")...)
		out = append(out, scanSchema(t, s.Origin)...)
		out = append(out, scanSchemaRefs(t, s.Origin)...)
	}

	for _, p := range s.Prompts {
		tgt := findings.Target{Tool: p.Name, Endpoint: s.Origin}
		for _, r := range promptRules {
			if r.Hit(p.Description) {
				out = append(out, fromRule(r, tgt, "prompt.description", p.Description))
			}
		}
		out = append(out, scanHidden(p.Name+"\n"+p.Description, tgt, "prompt")...)
	}

	out = append(out, scanShadowing(s)...)
	out = append(out, scanEncoded(s)...)
	out = append(out, scanPoison(s)...)
	return out
}

// TextKind labels where a text block came from so findings can say so.
type TextKind string

const (
	TextToolDescription TextKind = "tool.description"
	TextPromptMessages  TextKind = "prompt.messages"
	TextResource        TextKind = "resource.text"
	TextInstructions    TextKind = "server.instructions"
)

// Text runs the black/gray-box text detectors (pattern rules + hidden chars +
// prompt-injection pattern pass + prompt-defense coverage) over an arbitrary
// text block. It is the engine the black-box scanner uses to analyze prompt
// bodies, resource text, and the server's instructions field — content that is
// NOT in the declared surface and is only available through a live session.
//
// name is the target identifier (tool name, prompt name, resource URI, or
// server name for instructions); origin is the server endpoint; kind picks the
// detector slice used for pattern rules.
func (a *Analyzer) Text(kind TextKind, name, origin, text string) []findings.Finding {
	if text == "" {
		return nil
	}
	var out []findings.Finding
	tgt := findings.Target{Tool: name, Endpoint: origin}

	// Pattern rules that already fire on tool/prompt descriptions make sense
	// for prompt messages, resource text, and instructions too — those are all
	// text that the agent reads. We reuse the prompt-description rule set for
	// non-tool kinds and the tool-description set for tool content.
	var patternRules []rules.Rule
	switch kind {
	case TextToolDescription:
		patternRules = a.rules.ForField(rules.FieldToolDesc)
	default:
		patternRules = a.rules.ForField(rules.FieldPromptDesc)
	}
	for _, r := range patternRules {
		if r.Hit(text) {
			out = append(out, fromRule(r, tgt, string(kind), text))
		}
	}

	out = append(out, scanHidden(text, tgt, string(kind))...)

	// Prompt-defense: flags MISSING defensive language in the text.
	out = append(out, scanPromptDefenses(text, string(kind), name, origin)...)

	// Full-schema poisoning language (ignore/disregard, exfil keywords, hidden
	// URLs) applies to any readable text block.
	for _, p := range poisonPatterns {
		if strings.Contains(strings.ToLower(text), p.keyword) {
			f := findings.Finding{
				RuleID:     "B9." + string(kind) + ".poison",
				Class:      "B9",
				Title:      p.title,
				Severity:   findings.SeverityHigh,
				Confidence: findings.ConfidenceFirm,
				Modes:      []findings.Mode{findings.ModeBlack, findings.ModeGray},
				Target:     tgt,
				Evidence: findings.Evidence{
					Note: fmt.Sprintf(
						"%s %q contains the directive-like phrase %q — this kind of language in content the agent reads is a prompt-injection surface",
						kind, name, p.keyword,
					),
					SourceSnippet: excerptAround(text, p.keyword),
				},
				CWE:         "CWE-74",
				References:  []string{"full-schema-poisoning", string(kind)},
				Remediation: "Treat this content as data, not instructions, and strip or escape directive language before passing it to an LLM.",
				StageStatus: findings.StageCompleted,
			}
			f.ID = f.Fingerprint()
			out = append(out, f)
			break // one finding per block per rule
		}
	}
	return out
}

// excerptAround returns ~80 chars around the first occurrence of needle.
func excerptAround(text, needle string) string {
	lower := strings.ToLower(text)
	idx := strings.Index(lower, needle)
	if idx < 0 {
		return excerpt(text)
	}
	const window = 80
	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + window
	if end > len(text) {
		end = len(text)
	}
	snip := text[start:end]
	if start > 0 {
		snip = "…" + snip
	}
	if end < len(text) {
		snip += "…"
	}
	return snip
}

// Config runs the configuration detectors (B7) over a client configuration.
func (a *Analyzer) Config(c *manifest.Config) []findings.Finding {
	var out []findings.Finding
	cmdRules := a.rules.ForField(rules.FieldServerCmd)
	argRules := a.rules.ForField(rules.FieldServerArg)

	for _, srv := range c.Servers {
		tgt := findings.Target{Tool: srv.Name, Endpoint: srv.Name}
		for _, r := range cmdRules {
			if srv.Command != "" && r.Hit(srv.Command) {
				out = append(out, fromRule(r, tgt, "server.command", srv.Command))
			}
		}
		for _, arg := range srv.Args {
			for _, r := range argRules {
				if r.Hit(arg) {
					out = append(out, fromRule(r, tgt, "server.arg", arg))
				}
			}
		}
		out = append(out, threatdb.Match(srv.Name, srv.Command, srv.Args)...)
	}
	return out
}
