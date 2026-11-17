// Package report models a scan result and serializes it. A report keeps the
// status of every stage distinct, so a skipped or errored stage is never
// mistaken for a clean one.
package report

import (
	"time"

	"seyon/internal/findings"
)

// ScannerInfo identifies the tool that produced the report.
type ScannerInfo struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	SchemaVersion string `json:"schema_version"`
}

// Stage records the outcome of one stage of a scan for the target.
type Stage struct {
	Name   string               `json:"name"`
	Status findings.StageStatus `json:"status"`
	Detail string               `json:"detail,omitempty"`
}

// InventorySummary is a compact view of the enumerated surface.
type InventorySummary struct {
	Server    string `json:"server,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Transport string `json:"transport,omitempty"` // "streamable-http", "legacy-sse", "stdio"
	Endpoint  string `json:"endpoint,omitempty"`  // the URL/path the dialer actually bound to
	Tools     int    `json:"tools"`
	Resources int    `json:"resources"`
	Prompts   int    `json:"prompts"`
	Complete  bool   `json:"complete"`
}

// Report is the full result of a scan.
type Report struct {
	Scanner    ScannerInfo        `json:"scanner"`
	Target     string             `json:"target"`
	Modes      []findings.Mode    `json:"modes"`
	StartedAt  time.Time          `json:"started_at"`
	FinishedAt time.Time          `json:"finished_at"`
	Inventory  *InventorySummary  `json:"inventory,omitempty"`
	Stages     []Stage            `json:"stages"`
	Findings   []findings.Finding `json:"findings"`
}

// New returns a report initialized with scanner identity and start time.
func New(version, target string, modes []findings.Mode) *Report {
	return &Report{
		Scanner: ScannerInfo{
			Name:          "seyon",
			Version:       version,
			SchemaVersion: findings.SchemaVersion,
		},
		Target:    target,
		Modes:     modes,
		StartedAt: time.Now().UTC(),
		Findings:  []findings.Finding{},
		Stages:    []Stage{},
	}
}

// AddStage appends a stage outcome.
func (r *Report) AddStage(name string, status findings.StageStatus, detail string) {
	r.Stages = append(r.Stages, Stage{Name: name, Status: status, Detail: detail})
}

// Add appends findings.
// Add appends findings to the report, running Enrich() on each so the OWASP
// mapping and AITech taxonomy fields are populated. Detectors can safely
// construct a bare finding without calling Enrich themselves.
func (r *Report) Add(fs ...findings.Finding) {
	for i := range fs {
		fs[i].Enrich()
	}
	r.Findings = append(r.Findings, fs...)
}

// Finalize sorts and dedups findings and stamps the finish time.
func (r *Report) Finalize() {
	r.Findings = findings.Dedup(r.Findings)
	findings.Sort(r.Findings)
	r.FinishedAt = time.Now().UTC()
}

// Counts returns the number of findings per severity.
func (r *Report) Counts() map[findings.Severity]int {
	m := map[findings.Severity]int{}
	for _, f := range r.Findings {
		m[f.Severity]++
	}
	return m
}
