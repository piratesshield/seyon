package report

import (
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"seyon/internal/findings"
)

// WriteHTML writes a self-contained HTML report. The output is a single file
// with embedded CSS — no external dependencies — for easy sharing and offline
// viewing at conferences.
func WriteHTML(w io.Writer, r *Report) error {
	e := &errWriter{w: w}

	e.printf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Seyon Report</title>
<style>
:root {
  --bg: #0d1117; --fg: #c9d1d9; --border: #30363d;
  --card: #161b22; --accent: #58a6ff;
  --crit: #f85149; --high: #f0883e; --med: #d29922; --low: #3fb950; --info: #8b949e;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { background:var(--bg); color:var(--fg); font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; line-height:1.5; }
.container { max-width:1100px; margin:0 auto; padding:24px 16px; }
h1 { font-size:1.75rem; color:#fff; margin-bottom:4px; }
.subtitle { color:var(--accent); font-size:0.95rem; margin-bottom:24px; }
.meta { display:flex; gap:24px; flex-wrap:wrap; margin-bottom:24px; font-size:0.85rem; color:var(--info); }
.meta span { background:var(--card); padding:4px 12px; border-radius:6px; border:1px solid var(--border); }

.summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:12px; margin-bottom:32px; }
.stat { text-align:center; padding:16px 8px; border-radius:8px; background:var(--card); border:1px solid var(--border); }
.stat .num { font-size:2rem; font-weight:700; }
.stat .label { font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--info); }
.stat.critical .num { color:var(--crit); }
.stat.high .num { color:var(--high); }
.stat.medium .num { color:var(--med); }
.stat.low .num { color:var(--low); }
.stat.info .num { color:var(--info); }

.stages { margin-bottom:32px; }
.stages h2 { font-size:1.1rem; margin-bottom:12px; color:#fff; }
.stage-row { display:flex; justify-content:space-between; padding:6px 12px; border-bottom:1px solid var(--border); font-size:0.85rem; }
.stage-name { font-weight:600; }
.stage-status { padding:2px 8px; border-radius:4px; font-size:0.75rem; }
.status-completed { background:#1a3a1a; color:var(--low); }
.status-no_findings { background:#1a2a1a; color:var(--low); }
.status-error { background:#3a1a1a; color:var(--crit); }
.status-skipped { background:#2a2a1a; color:var(--med); }

.findings h2 { font-size:1.1rem; margin-bottom:12px; color:#fff; }
.finding { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:16px; margin-bottom:12px; border-left:4px solid; }
.finding.sev-critical { border-left-color:var(--crit); }
.finding.sev-high { border-left-color:var(--high); }
.finding.sev-medium { border-left-color:var(--med); }
.finding.sev-low { border-left-color:var(--low); }
.finding.sev-info { border-left-color:var(--info); }
.finding-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; }
.finding-title { font-weight:600; color:#fff; }
.badges { display:flex; gap:6px; }
.badge { padding:2px 8px; border-radius:4px; font-size:0.7rem; text-transform:uppercase; font-weight:600; }
.badge.sev { background:#2a1a1a; }
.badge.sev-critical { color:var(--crit); }
.badge.sev-high { color:var(--high); }
.badge.sev-medium { color:var(--med); }
.badge.sev-low { color:var(--low); }
.badge.sev-info { color:var(--info); }
.badge.conf { background:#1a1a2a; color:var(--accent); }
.badge.owasp { background:#1a2a2a; color:#79c0ff; }
.badge.mode { background:#1a1a1a; color:var(--info); }
.finding-detail { font-size:0.85rem; margin-top:8px; }
.finding-detail .label { color:var(--info); display:inline-block; width:80px; }
.evidence { background:var(--bg); padding:8px 12px; border-radius:4px; margin-top:8px; font-family:monospace; font-size:0.8rem; white-space:pre-wrap; word-break:break-all; }
.finding-id { font-family:monospace; font-size:0.7rem; color:var(--info); margin-top:6px; }

footer { text-align:center; padding:32px 0; color:var(--info); font-size:0.8rem; border-top:1px solid var(--border); margin-top:32px; }
</style>
</head>
<body>
<div class="container">
`)
	e.printf("<h1>Seyon Security Report</h1>\n")
	e.printf(`<div class="subtitle">%s v%s — schema v%s</div>`+"\n",
		html.EscapeString(r.Scanner.Name),
		html.EscapeString(r.Scanner.Version),
		html.EscapeString(r.Scanner.SchemaVersion))

	e.printf(`<div class="meta">`)
	e.printf(`<span>Target: %s</span>`, html.EscapeString(r.Target))
	modes := make([]string, len(r.Modes))
	for i, m := range r.Modes {
		modes[i] = string(m)
	}
	e.printf(`<span>Modes: %s</span>`, html.EscapeString(strings.Join(modes, ", ")))
	if !r.StartedAt.IsZero() {
		e.printf(`<span>%s</span>`, r.StartedAt.Format(time.RFC3339))
	}
	if r.Inventory != nil {
		e.printf(`<span>%d tools, %d resources, %d prompts</span>`,
			r.Inventory.Tools, r.Inventory.Resources, r.Inventory.Prompts)
	}
	e.printf("</div>\n")

	c := r.Counts()
	e.printf(`<div class="summary">`)
	for _, s := range []struct {
		sev   findings.Severity
		label string
	}{
		{findings.SeverityCritical, "Critical"},
		{findings.SeverityHigh, "High"},
		{findings.SeverityMedium, "Medium"},
		{findings.SeverityLow, "Low"},
		{findings.SeverityInfo, "Info"},
	} {
		e.printf(`<div class="stat %s"><div class="num">%d</div><div class="label">%s</div></div>`,
			string(s.sev), c[s.sev], s.label)
	}
	e.printf("</div>\n")

	e.printf(`<div class="stages"><h2>Scan Stages</h2>`)
	for _, s := range r.Stages {
		detail := ""
		if s.Detail != "" {
			detail = " — " + s.Detail
		}
		e.printf(`<div class="stage-row"><span class="stage-name">%s</span><span><span class="stage-status status-%s">%s</span>%s</span></div>`,
			html.EscapeString(s.Name),
			string(s.Status), string(s.Status),
			html.EscapeString(detail))
	}
	e.printf("</div>\n")

	e.printf(`<div class="findings"><h2>Findings (%d)</h2>`, len(r.Findings))
	for _, f := range r.Findings {
		sevClass := "sev-" + string(f.Severity)
		e.printf(`<div class="finding %s">`, sevClass)
		e.printf(`<div class="finding-header">`)
		e.printf(`<span class="finding-title">[%s] %s</span>`, html.EscapeString(f.Class), html.EscapeString(f.Title))
		e.printf(`<div class="badges">`)
		e.printf(`<span class="badge sev %s">%s</span>`, sevClass, f.Severity)
		e.printf(`<span class="badge conf">%s</span>`, f.Confidence)
		for _, o := range f.OWASPIDs {
			e.printf(`<span class="badge owasp">%s</span>`, o)
		}
		for _, m := range f.Modes {
			e.printf(`<span class="badge mode">%s</span>`, m)
		}
		e.printf("</div></div>\n")

		if f.Target.Tool != "" {
			e.printf(`<div class="finding-detail"><span class="label">Tool:</span> %s</div>`, html.EscapeString(f.Target.Tool))
		}
		if f.Target.Source != "" {
			e.printf(`<div class="finding-detail"><span class="label">Source:</span> %s</div>`, html.EscapeString(f.Target.Source))
		}
		if f.Target.Endpoint != "" {
			e.printf(`<div class="finding-detail"><span class="label">Endpoint:</span> %s</div>`, html.EscapeString(f.Target.Endpoint))
		}
		if f.CWE != "" {
			e.printf(`<div class="finding-detail"><span class="label">CWE:</span> %s</div>`, html.EscapeString(f.CWE))
		}
		if f.Remediation != "" {
			e.printf(`<div class="finding-detail"><span class="label">Fix:</span> %s</div>`, html.EscapeString(f.Remediation))
		}
		if f.Evidence.Note != "" {
			e.printf(`<div class="finding-detail"><span class="label">Why:</span></div>`)
			e.printf(`<div class="evidence">%s</div>`, html.EscapeString(f.Evidence.Note))
		}
		if f.Evidence.SourceSnippet != "" {
			e.printf(`<div class="finding-detail"><span class="label">Code:</span></div>`)
			e.printf(`<div class="evidence">%s</div>`, html.EscapeString(f.Evidence.SourceSnippet))
		}
		if f.Evidence.Request != "" {
			e.printf(`<div class="finding-detail"><span class="label">Request:</span></div>`)
			e.printf(`<div class="evidence">%s</div>`, html.EscapeString(f.Evidence.Request))
		}
		if f.Evidence.Response != "" {
			e.printf(`<div class="finding-detail"><span class="label">Response:</span></div>`)
			e.printf(`<div class="evidence">%s</div>`, html.EscapeString(f.Evidence.Response))
		}
		if len(f.References) > 0 {
			refs := make([]string, len(f.References))
			for ri, ref := range f.References {
				refs[ri] = html.EscapeString(ref)
			}
			e.printf(`<div class="finding-detail"><span class="label">Refs:</span> %s</div>`, strings.Join(refs, ", "))
		}
		e.printf(`<div class="finding-id">%s — %s</div>`, html.EscapeString(f.ID), html.EscapeString(f.RuleID))
		e.printf("</div>\n")
	}
	e.printf("</div>\n")

	e.printf(`<footer>Generated by Seyon %s at %s</footer>`,
		html.EscapeString(r.Scanner.Version),
		time.Now().UTC().Format(time.RFC3339))
	e.printf("\n</div>\n</body>\n</html>\n")
	return e.err
}

func init() {
	_ = fmt.Sprint // ensure fmt is used
}
