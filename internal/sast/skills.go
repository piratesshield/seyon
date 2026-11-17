package sast

import (
	"fmt"
	"path/filepath"
	"strings"

	"seyon/internal/findings"
)

// Agent skill/instruction files that shape LLM behavior. These are a new
// attack surface: an attacker who controls one can inject instructions that
// the agent will follow, including tool calls, data exfiltration, and
// privilege escalation.

var skillFileNames = map[string]bool{
	"skill.md":                        true,
	"claude.md":                       true,
	".claude.md":                      true,
	"cursorrules":                     true,
	".cursorrules":                    true,
	"instructions.md":                 true,
	"copilot-instructions.md":         true,
	".github/copilot-instructions.md": true,
}

var hooksFileNames = map[string]bool{
	"hooks.json":         true,
	".claude/hooks.json": true,
}

var skillInjectionPatterns = []struct {
	keyword string
	title   string
	sev     findings.Severity
}{
	{"ignore previous", "Instruction override in agent skill file", findings.SeverityCritical},
	{"ignore above", "Instruction override in agent skill file", findings.SeverityCritical},
	{"disregard previous", "Override directive in agent skill file", findings.SeverityHigh},
	{"disregard the above", "Override directive in agent skill file", findings.SeverityHigh},
	{"disregard all", "Override directive in agent skill file", findings.SeverityHigh},
	{"do not tell the user", "Concealment directive in agent skill file", findings.SeverityCritical},
	{"do not mention", "Concealment directive in agent skill file", findings.SeverityHigh},
	{"do not reveal", "Concealment directive in agent skill file", findings.SeverityHigh},
	{"send to http", "Exfiltration URL in agent skill file", findings.SeverityCritical},
	{"send to https", "Exfiltration URL in agent skill file", findings.SeverityCritical},
	{"curl ", "Shell command in agent skill file", findings.SeverityHigh},
	{"wget ", "Shell command in agent skill file", findings.SeverityHigh},
	{"exec(", "Code execution in agent skill file", findings.SeverityHigh},
	{"eval(", "Code execution in agent skill file", findings.SeverityHigh},
	{"base64", "Encoding reference in agent skill file", findings.SeverityMedium},
	{"<script", "HTML/script tag in agent skill file", findings.SeverityHigh},
	{"you are now", "Identity override in agent skill file", findings.SeverityCritical},
	{"you must always", "Coercive instruction in agent skill file", findings.SeverityHigh},
	{"system prompt", "System prompt reference in agent skill file", findings.SeverityMedium},
}

var hooksPatterns = []struct {
	keyword string
	title   string
	sev     findings.Severity
}{
	{"curl ", "Shell command in hooks config", findings.SeverityHigh},
	{"wget ", "Network fetch in hooks config", findings.SeverityHigh},
	{"rm -rf", "Destructive command in hooks config", findings.SeverityCritical},
	{"chmod", "Permission change in hooks config", findings.SeverityMedium},
	{"sudo", "Privilege escalation in hooks config", findings.SeverityCritical},
	{"|", "Pipe chain in hooks config", findings.SeverityMedium},
	{"base64", "Encoding in hooks config", findings.SeverityMedium},
	{"nc ", "Netcat in hooks config", findings.SeverityHigh},
	{"python -c", "Inline code execution in hooks config", findings.SeverityHigh},
	{"node -e", "Inline code execution in hooks config", findings.SeverityHigh},
}

func isSkillFile(rel string) bool {
	base := strings.ToLower(filepath.Base(rel))
	if skillFileNames[base] {
		return true
	}
	lower := strings.ToLower(rel)
	for name := range skillFileNames {
		if strings.HasSuffix(lower, name) {
			return true
		}
	}
	return false
}

func isHooksFile(rel string) bool {
	base := strings.ToLower(filepath.Base(rel))
	if hooksFileNames[base] {
		return true
	}
	lower := strings.ToLower(rel)
	for name := range hooksFileNames {
		if strings.HasSuffix(lower, name) {
			return true
		}
	}
	return false
}

func scanSkillFile(rel string, data []byte) []findings.Finding {
	text := strings.ToLower(string(data))
	var out []findings.Finding
	for _, p := range skillInjectionPatterns {
		if strings.Contains(text, p.keyword) {
			f := findings.Finding{
				RuleID:     "B10.skill.injection",
				Class:      "B10",
				Title:      p.title,
				Severity:   p.sev,
				Confidence: findings.ConfidenceFirm,
				Modes:      []findings.Mode{findings.ModeWhite},
				Target:     findings.Target{Source: rel},
				Evidence: findings.Evidence{
					Note:          fmt.Sprintf("agent skill file %q contains injection pattern %q — this keyword can manipulate LLM behavior when loaded as system instructions", rel, p.keyword),
					SourceSnippet: snippetAround(text, p.keyword),
				},
				CWE:         "CWE-74",
				Remediation: "Review agent skill/instruction files for injected directives. These files shape agent behavior and should be treated as security-critical configuration.",
				StageStatus: findings.StageCompleted,
			}
			f.ID = f.Fingerprint()
			out = append(out, f)
		}
	}
	return out
}

func scanHooksFile(rel string, data []byte) []findings.Finding {
	text := string(data)
	var out []findings.Finding
	for _, p := range hooksPatterns {
		if strings.Contains(text, p.keyword) {
			f := findings.Finding{
				RuleID:     "B10.hooks.risky",
				Class:      "B10",
				Title:      p.title,
				Severity:   p.sev,
				Confidence: findings.ConfidenceTentative,
				Modes:      []findings.Mode{findings.ModeWhite},
				Target:     findings.Target{Source: rel},
				Evidence: findings.Evidence{
					Note:          fmt.Sprintf("hooks config %q contains risky command pattern %q — hooks execute automatically on agent events and can be used for supply-chain attacks", rel, p.keyword),
					SourceSnippet: snippetAround(text, p.keyword),
				},
				CWE:         "CWE-78",
				Remediation: "Review hooks configurations for injected or risky commands. Hooks execute automatically and should be audited for supply-chain attacks.",
				StageStatus: findings.StageCompleted,
			}
			f.ID = f.Fingerprint()
			out = append(out, f)
		}
	}
	return out
}

func snippetAround(text, keyword string) string {
	idx := strings.Index(strings.ToLower(text), strings.ToLower(keyword))
	if idx < 0 {
		return ""
	}
	lines := strings.Split(text, "\n")
	charCount := 0
	targetLine := 0
	for i, line := range lines {
		charCount += len(line) + 1
		if charCount > idx {
			targetLine = i
			break
		}
	}
	start := targetLine - 1
	if start < 0 {
		start = 0
	}
	end := targetLine + 2
	if end > len(lines) {
		end = len(lines)
	}
	var out []string
	for i := start; i < end; i++ {
		marker := "  "
		if i == targetLine {
			marker = "> "
		}
		out = append(out, fmt.Sprintf("%s%4d | %s", marker, i+1, lines[i]))
	}
	return strings.Join(out, "\n")
}
