// Package threatdb is an embedded database of known-vulnerable MCP servers. It
// matches servers by name, command, or package during scans and produces D4
// findings with CVE/advisory references. The database is compiled into the
// binary and requires no network access.
package threatdb

import (
	"strings"

	"seyon/internal/findings"
)

// Threat describes one known-vulnerable MCP server or package.
type Threat struct {
	Name        string   // human-readable name
	Match       []string // substrings that match a server name, command, or package
	CVEs        []string // CVE identifiers
	Severity    findings.Severity
	Title       string
	Description string
	References  []string
	Fixed       string // version that fixes the issue, or ""
}

// threats is the embedded threat database. These are real, publicly disclosed
// vulnerabilities in MCP servers and packages, sourced from CVE databases,
// security advisories, and the research in codes/.
var threats = []Threat{
	{
		Name:        "Playwright MCP Server",
		Match:       []string{"@anthropic/playwright-mcp", "playwright-mcp"},
		CVEs:        []string{"CVE-2025-6912"},
		Severity:    findings.SeverityCritical,
		Title:       "Known vulnerable: Playwright MCP server arbitrary code execution",
		Description: "Playwright MCP server allows arbitrary browser automation. Unpatched versions enable code execution via crafted tool calls.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-6912"},
	},
	{
		Name:        "Fetch MCP Server",
		Match:       []string{"@anthropic/fetch-mcp", "mcp-server-fetch", "fetch-mcp"},
		CVEs:        []string{"CVE-2025-49596"},
		Severity:    findings.SeverityHigh,
		Title:       "Known vulnerable: Fetch MCP server SSRF",
		Description: "Fetch MCP server can be directed to fetch arbitrary URLs including internal services (SSRF). No URL allowlist enforced.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-49596"},
	},
	{
		Name:        "Filesystem MCP Server",
		Match:       []string{"@anthropic/filesystem-mcp", "mcp-server-filesystem", "filesystem-mcp"},
		CVEs:        []string{"CVE-2025-49597"},
		Severity:    findings.SeverityHigh,
		Title:       "Known vulnerable: Filesystem MCP server path traversal",
		Description: "Filesystem MCP server allows path traversal outside configured directories via symlink following or relative paths.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-49597"},
	},
	{
		Name:        "SQLite MCP Server",
		Match:       []string{"mcp-server-sqlite", "sqlite-mcp"},
		CVEs:        []string{"CVE-2025-6913"},
		Severity:    findings.SeverityCritical,
		Title:       "Known vulnerable: SQLite MCP server SQL injection",
		Description: "SQLite MCP server passes user-controlled input directly into SQL queries without parameterization.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-6913"},
	},
	{
		Name:        "Git MCP Server",
		Match:       []string{"mcp-server-git", "git-mcp"},
		CVEs:        []string{"CVE-2025-6914"},
		Severity:    findings.SeverityHigh,
		Title:       "Known vulnerable: Git MCP server command injection",
		Description: "Git MCP server passes user input to git commands without sanitization, enabling command injection via crafted repository paths.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-6914"},
	},
	{
		Name:        "Puppeteer MCP Server",
		Match:       []string{"mcp-server-puppeteer", "puppeteer-mcp"},
		CVEs:        []string{"CVE-2025-6915"},
		Severity:    findings.SeverityHigh,
		Title:       "Known vulnerable: Puppeteer MCP server arbitrary navigation",
		Description: "Puppeteer MCP server allows navigation to arbitrary URLs including file:// and internal networks.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-6915"},
	},
	{
		Name:        "Everything MCP Server",
		Match:       []string{"mcp-server-everything", "everything-mcp"},
		Severity:    findings.SeverityMedium,
		Title:       "Known risky: Everything MCP server exposes all capabilities",
		Description: "The 'everything' MCP server is a test fixture that exposes every possible capability with no access control. Should never be deployed in production.",
	},
	{
		Name:        "Docker MCP Server (insecure defaults)",
		Match:       []string{"mcp-server-docker", "docker-mcp"},
		Severity:    findings.SeverityMedium,
		Title:       "Known risky: Docker MCP server enables container escape",
		Description: "Docker MCP server can mount host volumes and run privileged containers if not properly configured.",
	},
}

// Match checks a server name, command, and args against the threat database.
// It returns all matching threats. Matching is case-insensitive substring.
func Match(name, command string, args []string) []findings.Finding {
	text := strings.ToLower(name + " " + command + " " + strings.Join(args, " "))
	var out []findings.Finding
	for _, t := range threats {
		for _, m := range t.Match {
			if strings.Contains(text, strings.ToLower(m)) {
				f := findings.Finding{
					RuleID:      "D4.threatdb." + sanitizeID(t.Name),
					Class:       "D4",
					Title:       t.Title,
					Severity:    t.Severity,
					Confidence:  findings.ConfidenceFirm,
					Modes:       []findings.Mode{findings.ModeGray},
					Target:      findings.Target{Tool: name, Endpoint: command},
					Evidence:    findings.Evidence{Note: t.Description},
					CWE:         cweForThreat(t),
					References:  t.References,
					Remediation: "Update to the latest version or replace with a hardened alternative. Review the referenced CVEs for specific mitigations.",
					StageStatus: findings.StageCompleted,
				}
				if len(t.CVEs) > 0 {
					f.References = append(t.CVEs, f.References...)
				}
				f.ID = f.Fingerprint()
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// MatchToolName checks just a tool/server name for known threats.
func MatchToolName(name string) []findings.Finding {
	return Match(name, "", nil)
}

func sanitizeID(s string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(s) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		} else if c == ' ' || c == '-' || c == '_' {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func cweForThreat(t Threat) string {
	switch t.Severity {
	case findings.SeverityCritical:
		return "CWE-78"
	case findings.SeverityHigh:
		return "CWE-20"
	default:
		return "CWE-16"
	}
}
