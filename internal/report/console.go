package report

import (
	"fmt"
	"io"
	"strings"

	"seyon/internal/findings"
)

// errWriter writes to w and remembers the first error, so a sequence of writes
// needs only one error check (the Fprintf-returns-error pattern).
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, a ...interface{}) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, a...)
}

// WriteConsole writes a human-readable summary of the report.
func WriteConsole(w io.Writer, r *Report) error {
	e := &errWriter{w: w}
	e.printf("seyon %s  —  target: %s\n", r.Scanner.Version, r.Target)
	if r.Inventory != nil {
		inv := r.Inventory
		complete := "complete"
		if !inv.Complete {
			complete = "INCOMPLETE"
		}
		e.printf("server: %s (protocol %s)\n", inv.Server, inv.Protocol)
		e.printf("surface: %d tools, %d resources, %d prompts [%s]\n",
			inv.Tools, inv.Resources, inv.Prompts, complete)
	}

	e.printf("\nstages:\n")
	for _, s := range r.Stages {
		detail := ""
		if s.Detail != "" {
			detail = " — " + s.Detail
		}
		e.printf("  %-22s %s%s\n", s.Name, s.Status, detail)
	}

	e.printf("\nfindings: %d\n", len(r.Findings))
	if len(r.Findings) == 0 {
		e.printf("  (none)\n")
	}
	for i, f := range r.Findings {
		e.printf("\n  ── finding %d/%d ────────────────────────────────────────\n", i+1, len(r.Findings))
		e.printf("  [%s/%s] %s  %s\n", f.Severity, f.Confidence, f.Class, f.Title)

		if f.Target.Tool != "" {
			e.printf("      tool:     %s\n", f.Target.Tool)
		}
		if f.Target.Source != "" {
			e.printf("      source:   %s\n", f.Target.Source)
		}
		if f.Target.Endpoint != "" {
			e.printf("      endpoint: %s\n", f.Target.Endpoint)
		}

		if f.CWE != "" {
			e.printf("      cwe:      %s\n", f.CWE)
		}
		if len(f.OWASPIDs) > 0 {
			ids := make([]string, len(f.OWASPIDs))
			for j, o := range f.OWASPIDs {
				ids[j] = string(o)
			}
			e.printf("      owasp:    %s\n", strings.Join(ids, ", "))
		}

		if f.Evidence.Note != "" {
			e.printf("      evidence: %s\n", f.Evidence.Note)
		}
		if f.Evidence.SourceSnippet != "" {
			e.printf("      snippet:\n")
			for _, line := range strings.Split(f.Evidence.SourceSnippet, "\n") {
				e.printf("        | %s\n", line)
			}
		}
		if f.Evidence.Request != "" {
			e.printf("      request:\n")
			for _, line := range strings.Split(f.Evidence.Request, "\n") {
				e.printf("        > %s\n", line)
			}
		}
		if f.Evidence.Response != "" {
			e.printf("      response:\n")
			for _, line := range strings.Split(f.Evidence.Response, "\n") {
				e.printf("        < %s\n", line)
			}
		}

		if f.Remediation != "" {
			e.printf("      fix:      %s\n", f.Remediation)
		}
		if len(f.References) > 0 {
			e.printf("      refs:     %s\n", strings.Join(f.References, ", "))
		}
		e.printf("      id:       %s  (%s)\n", f.ID, f.RuleID)
	}

	c := r.Counts()
	e.printf("\nsummary: %d critical, %d high, %d medium, %d low, %d info\n",
		c[findings.SeverityCritical], c[findings.SeverityHigh], c[findings.SeverityMedium],
		c[findings.SeverityLow], c[findings.SeverityInfo])
	return e.err
}
