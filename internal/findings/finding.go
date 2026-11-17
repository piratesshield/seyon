// Package findings defines Seyon's finding schema (v1): the stable record that
// every analyzer produces, the correlation engine merges, and the reporters
// serialize. Severity and confidence are deliberately independent axes.
package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// SchemaVersion is the version of the finding record emitted by this build.
const SchemaVersion = "2"

// Severity is how damaging a finding is if real. It is set by the finding class
// and the affected capability, and is independent of how sure we are.
type Severity string

// The severity levels, ordered most to least damaging.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// rank orders severities most-to-least severe for sorting and gating.
func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { return s.rank() != 0 }

// Confidence is how sure we are the finding is real, set by evidence quality
// and independent of severity.
type Confidence string

// The confidence levels, ordered most to least sure.
const (
	// ConfidenceConfirmed means the finding is proven by a canary or runtime observation.
	ConfidenceConfirmed Confidence = "confirmed"
	// ConfidenceFirm means dataflow reaches a sink, or a live probe returned a telling response.
	ConfidenceFirm Confidence = "firm"
	// ConfidenceTentative is a heuristic or single-signal match that needs triage.
	ConfidenceTentative Confidence = "tentative"
)

func (c Confidence) rank() int {
	switch c {
	case ConfidenceConfirmed:
		return 3
	case ConfidenceFirm:
		return 2
	case ConfidenceTentative:
		return 1
	default:
		return 0
	}
}

// Valid reports whether c is a known confidence.
func (c Confidence) Valid() bool { return c.rank() != 0 }

// Mode is a scanning vantage point.
type Mode string

// The scanning modes.
const (
	ModeBlack Mode = "black"
	ModeGray  Mode = "gray"
	ModeWhite Mode = "white"
)

// StageStatus records the outcome of a scan stage for a target. It keeps
// "clean" distinct from "never ran": a skipped or errored stage is never
// reported as evidence of safety.
type StageStatus string

// The stage outcomes. "No findings" is kept distinct from "not evaluated",
// "skipped", and "error", so a stage that did not run is never read as clean.
const (
	StageCompleted    StageStatus = "completed"
	StageNoFindings   StageStatus = "no_findings"
	StageNotEvaluated StageStatus = "not_evaluated"
	StageSkipped      StageStatus = "skipped"
	StageError        StageStatus = "error"
)

// Target locates what a finding is about. Any subset of fields may be set
// depending on the mode that produced it.
type Target struct {
	Tool     string `json:"tool,omitempty"`
	Resource string `json:"resource,omitempty"`
	Source   string `json:"source,omitempty"` // file:line
	Endpoint string `json:"endpoint,omitempty"`
}

// Evidence backs a finding. At least one field must be set — Seyon never ships
// a finding without evidence.
type Evidence struct {
	SourceSnippet string `json:"source_snippet,omitempty"`
	Canary        string `json:"canary,omitempty"`
	Request       string `json:"request,omitempty"`
	Response      string `json:"response,omitempty"`
	Note          string `json:"note,omitempty"`
}

func (e Evidence) empty() bool {
	return e.SourceSnippet == "" && e.Canary == "" && e.Request == "" &&
		e.Response == "" && e.Note == ""
}

// Finding is one security finding. It is the schema-v1 record.
type Finding struct {
	ID         string     `json:"id"`
	RuleID     string     `json:"rule_id"`
	Class      string     `json:"class"`
	Title      string     `json:"title"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Modes      []Mode     `json:"mode"`
	Target     Target     `json:"target"`
	Evidence   Evidence   `json:"evidence"`
	CWE        string     `json:"cwe,omitempty"`
	OWASPIDs   []OWASP    `json:"owasp,omitempty"`
	// AITech maps the finding to Cisco's AI Threat taxonomy
	// (AITech-X.Y / AISubtech-X.Y.Z). Populated by Enrich() when a mapping is
	// known for this rule's class. Omitted on findings that do not fit the
	// taxonomy (e.g. correlation-only findings).
	AITech      *AITechMapping `json:"aitech,omitempty"`
	References  []string       `json:"references,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	StageStatus StageStatus    `json:"stage_status"`
	// Related holds the IDs of the member findings a correlated (class "X")
	// finding ties together. It is empty on ordinary findings.
	Related []string `json:"related,omitempty"`
}

// Enrich populates derived fields (OWASP mapping, AITech taxonomy) from the
// finding's class/rule ID. Call it after setting Class/RuleID but before
// emitting the finding.
func (f *Finding) Enrich() {
	if len(f.OWASPIDs) == 0 {
		f.OWASPIDs = OWASPForClass(f.Class)
	}
	if f.AITech == nil {
		f.AITech = AITechForRule(f.Class, f.RuleID)
	}
}

// Fingerprint returns a stable identity for the finding, derived from the
// properties that make two reports "the same issue" (rule, class, and the
// located target). It is used for dedup and correlation and does not depend on
// evidence text, which varies between runs.
func (f Finding) Fingerprint() string {
	h := sha256.New()
	parts := []string{
		f.RuleID, f.Class,
		f.Target.Tool, f.Target.Resource, f.Target.Source, f.Target.Endpoint,
	}
	h.Write([]byte(strings.Join(parts, "\x00")))
	return "SEYON-" + hex.EncodeToString(h.Sum(nil))[:12]
}

// Validate checks required invariants: known severity/confidence, a class and
// title, a stage status, and — for a completed finding — attached evidence.
func (f Finding) Validate() error {
	switch {
	case f.Class == "":
		return &ValidationError{"class is required"}
	case f.Title == "":
		return &ValidationError{"title is required"}
	case !f.Severity.Valid():
		return &ValidationError{"invalid severity: " + string(f.Severity)}
	case !f.Confidence.Valid():
		return &ValidationError{"invalid confidence: " + string(f.Confidence)}
	case f.StageStatus == "":
		return &ValidationError{"stage_status is required"}
	case f.Evidence.empty():
		return &ValidationError{"a finding must carry evidence"}
	}
	return nil
}

// ValidationError is returned by Validate.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return "finding: " + e.Msg }

// Sort orders findings most-severe first, then by confidence, then by ID, so
// report output is deterministic.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.rank() != b.Severity.rank() {
			return a.Severity.rank() > b.Severity.rank()
		}
		if a.Confidence.rank() != b.Confidence.rank() {
			return a.Confidence.rank() > b.Confidence.rank()
		}
		return a.ID < b.ID
	})
}

// Dedup collapses findings that share a fingerprint, keeping the first seen and
// unioning their modes. It preserves input order of the survivors. It also
// enriches each surviving finding with derived fields (OWASP mapping).
func Dedup(fs []Finding) []Finding {
	seen := make(map[string]int, len(fs))
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		f.Enrich()
		fp := f.Fingerprint()
		if idx, ok := seen[fp]; ok {
			out[idx].Modes = unionModes(out[idx].Modes, f.Modes)
			continue
		}
		seen[fp] = len(out)
		out = append(out, f)
	}
	return out
}

func unionModes(a, b []Mode) []Mode {
	set := make(map[Mode]bool, len(a)+len(b))
	var out []Mode
	for _, m := range append(append([]Mode{}, a...), b...) {
		if !set[m] {
			set[m] = true
			out = append(out, m)
		}
	}
	return out
}
