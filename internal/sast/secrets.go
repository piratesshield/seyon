package sast

import (
	"regexp"
	"strings"

	"seyon/internal/findings"
)

// secretPattern matches a hardcoded secret. Specific, well-known shapes are
// reported firm; the generic assignment heuristic is tentative.
type secretPattern struct {
	id         string
	title      string
	re         *regexp.Regexp
	severity   findings.Severity
	confidence findings.Confidence
}

type secretScanner struct {
	pats []secretPattern
}

func newSecretScanner() *secretScanner {
	p := func(id, title, re string, sev findings.Severity, conf findings.Confidence) secretPattern {
		return secretPattern{id, title, regexp.MustCompile(re), sev, conf}
	}
	return &secretScanner{pats: []secretPattern{
		p("C5.aws-access-key", "Hardcoded AWS access key id", `\bAKIA[0-9A-Z]{16}\b`, findings.SeverityHigh, findings.ConfidenceFirm),
		p("C5.private-key", "Hardcoded private key", `-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`, findings.SeverityHigh, findings.ConfidenceFirm),
		p("C5.slack-token", "Hardcoded Slack token", `\bxox[baprs]-[0-9A-Za-z-]{10,}\b`, findings.SeverityHigh, findings.ConfidenceFirm),
		p("C5.github-token", "Hardcoded GitHub token", `\bghp_[0-9A-Za-z]{36}\b`, findings.SeverityHigh, findings.ConfidenceFirm),
		p("C5.generic-assignment", "Possible hardcoded secret in assignment",
			`(?i)(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*["'][A-Za-z0-9/+_\-]{16,}["']`,
			findings.SeverityMedium, findings.ConfidenceTentative),
	}}
}

// scan reports secret findings in a file, one per (pattern,line).
func (s *secretScanner) scan(rel string, data []byte) []findings.Finding {
	var out []findings.Finding
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if len(line) > 4000 {
			line = line[:4000] // avoid pathological regex cost on minified blobs
		}
		for _, p := range s.pats {
			if p.re.MatchString(line) {
				f := findings.Finding{
					RuleID:      p.id,
					Class:       "C5",
					Title:       p.title,
					Severity:    p.severity,
					Confidence:  p.confidence,
					Modes:       []findings.Mode{findings.ModeWhite},
					Target:      findings.Target{Source: rel + ":" + itoa(i+1)},
					Evidence:    findings.Evidence{Note: "secret-like value on this line (redacted)"},
					CWE:         "CWE-798",
					References:  []string{"secrets"},
					Remediation: "Remove the secret from source; load it from the environment or a secrets manager and rotate the exposed value.",
					StageStatus: findings.StageCompleted,
				}
				f.ID = f.Fingerprint()
				out = append(out, f)
			}
		}
	}
	return out
}

// itoa is a tiny int→string without importing strconv across the package.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
