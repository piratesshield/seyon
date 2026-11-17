package sast

import (
	"regexp"
	"strings"

	"seyon/internal/findings"
)

var (
	rePipeShell = regexp.MustCompile(`(?i)(curl|wget)\b[^\n]*\|\s*(sh|bash)`)
	reAddRemote = regexp.MustCompile(`(?i)^\s*ADD\s+https?://`)
	reUserRoot  = regexp.MustCompile(`(?i)^\s*USER\s+(root|0)\s*$`)
	reUserAny   = regexp.MustCompile(`(?i)^\s*USER\s+`)
)

// scanDockerfile reports D3 posture issues: fetch-piped-to-shell in RUN, remote
// ADD, running as root, and the absence of any non-root USER directive.
func scanDockerfile(rel string, data []byte) []findings.Finding {
	var out []findings.Finding
	lines := strings.Split(string(data), "\n")
	sawUser, sawNonRootUser := false, false

	add := func(line int, id, title string, sev findings.Severity, conf findings.Confidence, note, rem string) {
		loc := rel
		if line > 0 {
			loc = rel + ":" + itoa(line)
		}
		f := findings.Finding{
			RuleID:      id,
			Class:       "D3",
			Title:       title,
			Severity:    sev,
			Confidence:  conf,
			Modes:       []findings.Mode{findings.ModeWhite},
			Target:      findings.Target{Source: loc},
			Evidence:    findings.Evidence{Note: note},
			References:  []string{"container-hardening"},
			Remediation: rem,
			StageStatus: findings.StageCompleted,
		}
		f.ID = f.Fingerprint()
		out = append(out, f)
	}

	for i, line := range lines {
		switch {
		case rePipeShell.MatchString(line):
			add(i+1, "D3.run-pipe-shell", "Dockerfile fetches and pipes remote code into a shell",
				findings.SeverityHigh, findings.ConfidenceFirm,
				strings.TrimSpace(line),
				"Do not pipe a remote download into a shell at build time; fetch, verify, and copy a pinned artifact.")
		case reAddRemote.MatchString(line):
			add(i+1, "D3.add-remote", "Dockerfile ADDs a remote URL",
				findings.SeverityMedium, findings.ConfidenceFirm,
				strings.TrimSpace(line),
				"Use COPY with a vendored, verified file instead of ADD of a remote URL.")
		}
		if reUserAny.MatchString(line) {
			sawUser = true
			if !reUserRoot.MatchString(line) {
				sawNonRootUser = true
			} else {
				add(i+1, "D3.user-root", "Dockerfile sets USER root",
					findings.SeverityMedium, findings.ConfidenceFirm,
					strings.TrimSpace(line),
					"Run the server as a non-root user; drop privileges with a dedicated USER.")
			}
		}
	}

	if !sawUser || !sawNonRootUser {
		add(0, "D3.no-user", "Dockerfile does not drop to a non-root user",
			findings.SeverityLow, findings.ConfidenceTentative,
			"no non-root USER directive found",
			"Add a non-root USER so the MCP server does not run as root in the container.")
	}
	return out
}
