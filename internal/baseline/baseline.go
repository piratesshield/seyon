// Package baseline pins a trusted snapshot of a server's surface and detects
// drift against it: changed (rug-pull), added, or removed tool definitions.
// This is the B4 detector.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"seyon/internal/findings"
	"seyon/internal/surface"
)

// Baseline is a trusted snapshot: a hash per tool definition.
type Baseline struct {
	Server    string            `json:"server,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	ToolHash  map[string]string `json:"tool_hash"`
}

// hashTool returns a stable hash over the parts of a tool the agent trusts:
// its name, description, and input schema.
func hashTool(name, desc string, schema json.RawMessage) string {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write([]byte(desc))
	h.Write([]byte{0})
	h.Write([]byte(schema))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Compute builds a baseline from a surface.
func Compute(s *surface.Surface) *Baseline {
	b := &Baseline{Server: s.Server, CreatedAt: time.Now().UTC(), ToolHash: map[string]string{}}
	for _, t := range s.Tools {
		b.ToolHash[t.Name] = hashTool(t.Name, t.Description, t.InputSchema)
	}
	return b
}

// Save writes the baseline as JSON.
func Save(w io.Writer, b *Baseline) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}

// Load reads a baseline from JSON.
func Load(r io.Reader) (*Baseline, error) {
	var b Baseline
	if err := json.NewDecoder(r).Decode(&b); err != nil {
		return nil, fmt.Errorf("baseline: load: %w", err)
	}
	if b.ToolHash == nil {
		b.ToolHash = map[string]string{}
	}
	return &b, nil
}

// Diff compares the current surface against the baseline and returns B4
// findings: a changed definition is a rug-pull (high), a new tool is a new
// capability to review (medium), and a removed tool is informational.
func Diff(old *Baseline, s *surface.Surface) []findings.Finding {
	var out []findings.Finding
	current := map[string]string{}
	names := make([]string, 0, len(s.Tools))
	for _, t := range s.Tools {
		current[t.Name] = hashTool(t.Name, t.Description, t.InputSchema)
		names = append(names, t.Name)
	}
	sort.Strings(names)

	for _, name := range names {
		prev, existed := old.ToolHash[name]
		switch {
		case !existed:
			out = append(out, b4(name, s.Origin,
				findings.SeverityMedium, findings.ConfidenceFirm,
				"New tool appeared since the trusted baseline",
				"A tool not present in the baseline is now offered. Review it before trusting it."))
		case prev != current[name]:
			out = append(out, b4(name, s.Origin,
				findings.SeverityHigh, findings.ConfidenceFirm,
				"Tool definition changed since the trusted baseline (possible rug-pull)",
				"A previously approved tool's definition changed. Re-review the new definition; silent mutation after approval is a rug-pull."))
		}
	}

	// Removed tools (in baseline, gone now).
	removed := make([]string, 0)
	for name := range old.ToolHash {
		if _, ok := current[name]; !ok {
			removed = append(removed, name)
		}
	}
	sort.Strings(removed)
	for _, name := range removed {
		out = append(out, b4(name, s.Origin,
			findings.SeverityInfo, findings.ConfidenceFirm,
			"Tool present in the baseline is no longer offered",
			"A baselined tool disappeared. Confirm this is an intended change."))
	}
	return out
}

func b4(tool, origin string, sev findings.Severity, conf findings.Confidence, title, rem string) findings.Finding {
	f := findings.Finding{
		RuleID:      "B4.drift",
		Class:       "B4",
		Title:       title,
		Severity:    sev,
		Confidence:  conf,
		Modes:       []findings.Mode{findings.ModeGray},
		Target:      findings.Target{Tool: tool, Endpoint: origin},
		Evidence:    findings.Evidence{Note: "baseline comparison for tool " + tool},
		References:  []string{"rug-pull", "tool-mutation"},
		Remediation: rem,
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return f
}
