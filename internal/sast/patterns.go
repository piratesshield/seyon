package sast

import (
	"embed"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"seyon/internal/findings"
)

//go:embed patterns.yaml
var patternsFS embed.FS

type sourcePattern struct {
	ID          string   `yaml:"id"`
	Class       string   `yaml:"class"`
	Severity    string   `yaml:"severity"`
	Confidence  string   `yaml:"confidence"`
	Title       string   `yaml:"title"`
	CWE         string   `yaml:"cwe"`
	Langs       []string `yaml:"langs"`
	Regex       string   `yaml:"regex"`
	Remediation string   `yaml:"remediation"`

	re      *regexp.Regexp
	langSet map[string]bool
}

type patternEngine struct {
	pats []sourcePattern
}

func loadPatternEngine() (*patternEngine, error) {
	b, err := patternsFS.ReadFile("patterns.yaml")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Patterns []sourcePattern `yaml:"patterns"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("sast: parse patterns: %w", err)
	}
	pe := &patternEngine{}
	for i := range doc.Patterns {
		p := doc.Patterns[i]
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("sast: pattern %s: bad regex: %w", p.ID, err)
		}
		p.re = re
		p.langSet = map[string]bool{}
		for _, l := range p.Langs {
			p.langSet[l] = true
		}
		pe.pats = append(pe.pats, p)
	}
	return pe, nil
}

// scan applies the patterns for the given language to each line of a source
// file. Every match is reported at the pattern's (tentative) confidence.
func isCommentLine(line, lang string) bool {
	t := strings.TrimSpace(line)
	switch lang {
	case "javascript":
		return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*")
	case "python":
		return strings.HasPrefix(t, "#")
	}
	return false
}

func (pe *patternEngine) scan(rel, lang string, data []byte) []findings.Finding {
	var out []findings.Finding
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if len(line) > 4000 {
			line = line[:4000]
		}
		if isCommentLine(line, lang) {
			continue
		}
		for _, p := range pe.pats {
			if !p.langSet[lang] || !p.re.MatchString(line) {
				continue
			}
			f := findings.Finding{
				RuleID:      p.ID,
				Class:       p.Class,
				Title:       p.Title,
				Severity:    findings.Severity(p.Severity),
				Confidence:  findings.Confidence(p.Confidence),
				Modes:       []findings.Mode{findings.ModeWhite},
				Target:      findings.Target{Source: rel + ":" + itoa(i+1)},
				Evidence:    findings.Evidence{SourceSnippet: strings.TrimSpace(line)},
				CWE:         p.CWE,
				References:  []string{"static-pattern"},
				Remediation: p.Remediation,
				StageStatus: findings.StageCompleted,
			}
			f.ID = f.Fingerprint()
			out = append(out, f)
		}
	}
	return out
}
