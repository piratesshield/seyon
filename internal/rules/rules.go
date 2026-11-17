// Package rules is Seyon's declarative rule engine. Most gray-box detection is
// expressed as data — substring and regex patterns matched against a named
// field of a tool, prompt, or server spec — so rule packs ship and change
// without recompiling the binary.
package rules

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Field names a piece of the target a rule matches against.
type Field string

// The fields a rule can match against.
const (
	FieldToolName    Field = "tool.name"
	FieldToolDesc    Field = "tool.description"
	FieldPromptDesc  Field = "prompt.description"
	FieldServerCmd   Field = "server.command"
	FieldServerArg   Field = "server.arg"
	FieldResourceURI Field = "resource.uri"
)

var validFields = map[Field]bool{
	FieldToolName: true, FieldToolDesc: true, FieldPromptDesc: true,
	FieldServerCmd: true, FieldServerArg: true, FieldResourceURI: true,
}

var validSeverity = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
var validConfidence = map[string]bool{"confirmed": true, "firm": true, "tentative": true}

// Match is the condition part of a rule.
type Match struct {
	Field        Field    `yaml:"field"`
	AnySubstring []string `yaml:"any_substring"`
	AnyRegex     []string `yaml:"any_regex"`
}

// Rule is one declarative detection rule.
type Rule struct {
	ID          string   `yaml:"id"`
	Class       string   `yaml:"class"`
	Severity    string   `yaml:"severity"`
	Confidence  string   `yaml:"confidence"`
	Title       string   `yaml:"title"`
	CWE         string   `yaml:"cwe"`
	References  []string `yaml:"references"`
	Remediation string   `yaml:"remediation"`
	Match       Match    `yaml:"match"`

	regexes []*regexp.Regexp
	subs    []string // lower-cased substrings
}

// RuleSet is a loaded collection of rules.
type RuleSet struct {
	Rules []Rule
}

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// Load parses and validates a YAML rule pack, compiling its patterns.
func Load(b []byte) (*RuleSet, error) {
	var rf ruleFile
	if err := yaml.Unmarshal(b, &rf); err != nil {
		return nil, fmt.Errorf("rules: parse: %w", err)
	}
	rs := &RuleSet{}
	seen := map[string]bool{}
	for i := range rf.Rules {
		r := rf.Rules[i]
		if err := r.validate(); err != nil {
			return nil, err
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("rules: duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		for _, p := range r.Match.AnyRegex {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("rules: %s: bad regex %q: %w", r.ID, p, err)
			}
			r.regexes = append(r.regexes, re)
		}
		for _, s := range r.Match.AnySubstring {
			r.subs = append(r.subs, strings.ToLower(s))
		}
		rs.Rules = append(rs.Rules, r)
	}
	return rs, nil
}

func (r Rule) validate() error {
	switch {
	case r.ID == "":
		return fmt.Errorf("rules: a rule is missing an id")
	case r.Class == "":
		return fmt.Errorf("rules: %s: missing class", r.ID)
	case r.Title == "":
		return fmt.Errorf("rules: %s: missing title", r.ID)
	case !validSeverity[r.Severity]:
		return fmt.Errorf("rules: %s: invalid severity %q", r.ID, r.Severity)
	case !validConfidence[r.Confidence]:
		return fmt.Errorf("rules: %s: invalid confidence %q", r.ID, r.Confidence)
	case !validFields[r.Match.Field]:
		return fmt.Errorf("rules: %s: invalid match field %q", r.ID, r.Match.Field)
	case len(r.Match.AnySubstring) == 0 && len(r.Match.AnyRegex) == 0:
		return fmt.Errorf("rules: %s: match has no patterns", r.ID)
	}
	return nil
}

// ForField returns the rules that match against the given field.
func (rs *RuleSet) ForField(f Field) []Rule {
	var out []Rule
	for _, r := range rs.Rules {
		if r.Match.Field == f {
			out = append(out, r)
		}
	}
	return out
}

// Hit reports whether value triggers the rule. Substring matching is
// case-insensitive; regex matching uses the pattern as written.
func (r Rule) Hit(value string) bool {
	lower := strings.ToLower(value)
	for _, s := range r.subs {
		if strings.Contains(lower, s) {
			return true
		}
	}
	for _, re := range r.regexes {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}
