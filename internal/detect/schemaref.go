package detect

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"seyon/internal/findings"
	"seyon/internal/mcp"
)

// Bounds: schemas can be deeply nested JSON. Walk at most this many nodes and
// emit at most this many $ref findings per tool, so a hostile server cannot
// make the scanner run forever on a pathological schema.
const (
	schemaRefMaxNodes = 5000
	schemaRefMaxRefs  = 32
	schemaRefMaxDepth = 64
)

// scanSchemaRefs walks a tool's input/output schemas looking for $ref values
// that point outside the local document. A JSON Schema $ref that resolves to
// a remote URL or a file path is a form of indirect content: the client that
// dereferences it may pull in arbitrary text that then shapes the agent's
// behavior. Local fragment refs ("#/$defs/Foo") are skipped as they can only
// reference the same document.
//
// Classification (severity):
//   - file:// URI               → HIGH    (loads from local disk)
//   - localhost / private IP    → HIGH    (SSRF to internal services)
//   - http(s) external URL      → MEDIUM  (remote content pulled at use time)
//   - non-HTTP URI with scheme  → INFO
//   - relative / malformed      → INFO
func scanSchemaRefs(t mcp.Tool, origin string) []findings.Finding {
	var out []findings.Finding

	add := func(schemaField string) {
		if len(t.InputSchema) == 0 && schemaField == "inputSchema" {
			return
		}
		var raw json.RawMessage
		if schemaField == "inputSchema" {
			raw = t.InputSchema
		} else {
			// Tool struct does not have OutputSchema yet; future extension.
			return
		}
		if len(raw) == 0 {
			return
		}
		var root interface{}
		if err := json.Unmarshal(raw, &root); err != nil {
			return
		}
		walk := refWalker{
			tool:        t.Name,
			origin:      origin,
			schemaField: schemaField,
		}
		walk.push(root, schemaField, 0)
		for len(walk.stack) > 0 && walk.nodes < schemaRefMaxNodes && len(walk.found) < schemaRefMaxRefs {
			ent := walk.stack[len(walk.stack)-1]
			walk.stack = walk.stack[:len(walk.stack)-1]
			walk.nodes++
			walk.visit(ent)
		}
		out = append(out, walk.found...)
	}
	add("inputSchema")
	return out
}

type refEntry struct {
	value interface{}
	path  string
	depth int
}

type refWalker struct {
	stack       []refEntry
	nodes       int
	found       []findings.Finding
	tool        string
	origin      string
	schemaField string
}

func (w *refWalker) push(v interface{}, path string, depth int) {
	if depth > schemaRefMaxDepth {
		return
	}
	w.stack = append(w.stack, refEntry{value: v, path: path, depth: depth})
}

func (w *refWalker) visit(e refEntry) {
	switch v := e.value.(type) {
	case map[string]interface{}:
		if refVal, ok := v["$ref"].(string); ok {
			w.classify(refVal, e.path+".$ref")
		}
		for k, child := range v {
			w.push(child, e.path+"."+k, e.depth+1)
		}
	case []interface{}:
		for i, child := range v {
			w.push(child, fmt.Sprintf("%s[%d]", e.path, i), e.depth+1)
		}
	}
}

func (w *refWalker) classify(ref, path string) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") {
		// Local document fragment; nothing to pull in.
		return
	}
	severity, category, remediation := classifyRef(ref)
	if severity == "" {
		return
	}
	f := findings.Finding{
		RuleID:     "B9.schema.ref-" + category,
		Class:      "B9",
		Title:      "Tool input schema contains an external $ref",
		Severity:   severity,
		Confidence: findings.ConfidenceFirm,
		Modes:      []findings.Mode{findings.ModeGray},
		Target:     findings.Target{Tool: w.tool, Endpoint: w.origin},
		Evidence: findings.Evidence{
			Note: fmt.Sprintf(
				"tool %q declares a %s $ref at %s; a client that resolves it loads content from an external source into the schema that the agent then obeys",
				w.tool, category, path,
			),
			SourceSnippet: excerpt(ref),
		},
		CWE:         "CWE-611",
		References:  []string{"schema-reference-poisoning", "owasp-mcp-top-10:B9"},
		Remediation: remediation,
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	w.found = append(w.found, f)
}

// classifyRef returns (severity, short category label, remediation). Empty
// severity means "don't emit a finding".
func classifyRef(ref string) (findings.Severity, string, string) {
	u, err := url.Parse(ref)
	if err != nil {
		return findings.SeverityInfo, "malformed",
			"Remove the malformed $ref value from the schema."
	}
	switch strings.ToLower(u.Scheme) {
	case "file":
		return findings.SeverityHigh, "local-file",
			"Schemas must not reference local files via $ref. Inline the schema fragment, or move it to a trusted internal document and reference via #/..."
	case "http", "https":
		host := u.Hostname()
		if host == "" {
			return findings.SeverityMedium, "external-network",
				"Remove the external-network $ref. If the schema must be shared, embed it directly or pin to a trusted internal document."
		}
		lower := strings.ToLower(host)
		if lower == "localhost" ||
			strings.HasSuffix(lower, ".localhost") ||
			strings.HasSuffix(lower, ".local") ||
			isPrivateHost(host) {
			return findings.SeverityHigh, "private-network",
				"The $ref points at a private-network host. If a client resolves it, it fetches internal content under the agent's identity — a form of SSRF. Replace with an inline schema."
		}
		return findings.SeverityMedium, "external-network",
			"Remove the external-network $ref. If the schema must be shared, embed it directly or pin to a trusted internal document."
	case "":
		// Relative ref — may resolve against the tool's own origin.
		return findings.SeverityInfo, "relative",
			"Relative $ref values resolve against the client's base URL; prefer explicit, inlined schemas."
	default:
		return findings.SeverityInfo, "non-http",
			"Remove the non-HTTP $ref value or justify its scheme in a comment."
	}
}

// isPrivateHost reports whether host resolves to (or already is) a private
// IPv4/IPv6 or loopback address. Hostname-only resolution is not performed
// (the dialer can't be relied on for scan-time host lookups), so this only
// catches literal IPs; the lowercase-localhost checks above cover the name case.
func isPrivateHost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	return false
}
