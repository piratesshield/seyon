package detect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"seyon/internal/findings"
	"seyon/internal/surface"
)

var encodedThreatWords = []string{
	"ignore", "override", "system", "execute", "exec(",
	"eval(", "os.system", "subprocess", "child_process",
	"fetch(", "XMLHttpRequest", "<script", "javascript:",
	"file://", "data:", "curl ", "wget ", "nc ",
	"\\x", "\\u00", "passwd", "/etc/shadow",
	"DROP TABLE", "SELECT ", "UNION ", "INSERT ",
	"rm -rf", "chmod ", "sudo ",
}

// scanEncoded checks whether a tool's text fields contain base64-encoded,
// URL-encoded, or Unicode-escaped strings that decode to suspicious content.
// Attackers use encoding to evade simple pattern-based scanners.
func scanEncoded(s *surface.Surface) []findings.Finding {
	var out []findings.Finding
	for _, t := range s.Tools {
		tgt := findings.Target{Tool: t.Name, Endpoint: s.Origin}
		fields := map[string]string{
			"tool.description": t.Description,
			"tool.name":        t.Name,
		}
		for k, v := range schemaStrings(t.InputSchema) {
			fields["schema."+k] = v
		}
		for fieldName, text := range fields {
			out = append(out, checkEncoded(text, tgt, fieldName)...)
		}
	}
	return out
}

// schemaStrings extracts all string values from a JSON Schema object for
// scanning (property descriptions, defaults, enum values, titles, examples).
func schemaStrings(raw json.RawMessage) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var schema map[string]json.RawMessage
	if json.Unmarshal(raw, &schema) != nil {
		return nil
	}
	out := map[string]string{}
	extractSchemaStrings("", schema, out, 0)
	return out
}

func extractSchemaStrings(prefix string, obj map[string]json.RawMessage, out map[string]string, depth int) {
	if depth > 5 {
		return
	}
	for _, key := range []string{"title", "description", "default"} {
		if v, ok := obj[key]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil && s != "" {
				out[prefix+key] = s
			}
		}
	}
	if v, ok := obj["enum"]; ok {
		var items []json.RawMessage
		if json.Unmarshal(v, &items) == nil {
			for i, item := range items {
				var s string
				if json.Unmarshal(item, &s) == nil && s != "" {
					out[fmt.Sprintf("%senum[%d]", prefix, i)] = s
				}
			}
		}
	}
	if props, ok := obj["properties"]; ok {
		var propMap map[string]json.RawMessage
		if json.Unmarshal(props, &propMap) == nil {
			for name, propRaw := range propMap {
				var propObj map[string]json.RawMessage
				if json.Unmarshal(propRaw, &propObj) == nil {
					extractSchemaStrings(prefix+name+".", propObj, out, depth+1)
				}
			}
		}
	}
}

func checkEncoded(text string, tgt findings.Target, field string) []findings.Finding {
	var out []findings.Finding

	for _, segment := range extractBase64Candidates(text) {
		decoded, err := base64.StdEncoding.DecodeString(segment)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(segment)
		}
		if err != nil || len(decoded) < 8 || !utf8.Valid(decoded) {
			continue
		}
		if threat := matchThreat(string(decoded)); threat != "" {
			f := findings.Finding{
				RuleID:     "B8.encoded.base64",
				Class:      "B8",
				Title:      "Base64-encoded suspicious content in " + field,
				Severity:   findings.SeverityHigh,
				Confidence: findings.ConfidenceFirm,
				Modes:      []findings.Mode{findings.ModeGray},
				Target:     tgt,
				Evidence: findings.Evidence{
					Note:          field + " contains base64 that decodes to: " + excerpt(string(decoded)),
					SourceSnippet: excerpt(segment),
				},
				CWE:         "CWE-116",
				Remediation: "Remove encoded content from tool metadata. Encoded payloads in tool descriptions are a strong indicator of injection evasion.",
				StageStatus: findings.StageCompleted,
			}
			f.ID = f.Fingerprint()
			out = append(out, f)
		}
	}

	if decoded, err := url.QueryUnescape(text); err == nil && decoded != text {
		if threat := matchThreat(decoded); threat != "" {
			f := findings.Finding{
				RuleID:     "B8.encoded.urlencode",
				Class:      "B8",
				Title:      "URL-encoded suspicious content in " + field,
				Severity:   findings.SeverityHigh,
				Confidence: findings.ConfidenceFirm,
				Modes:      []findings.Mode{findings.ModeGray},
				Target:     tgt,
				Evidence: findings.Evidence{
					Note: field + " URL-decodes to: " + excerpt(decoded),
				},
				CWE:         "CWE-116",
				Remediation: "Remove URL-encoded content from tool metadata.",
				StageStatus: findings.StageCompleted,
			}
			f.ID = f.Fingerprint()
			out = append(out, f)
		}
	}

	if unescaped := unescapeUnicode(text); unescaped != text {
		if threat := matchThreat(unescaped); threat != "" {
			f := findings.Finding{
				RuleID:     "B8.encoded.unicode",
				Class:      "B8",
				Title:      "Unicode-escaped suspicious content in " + field,
				Severity:   findings.SeverityHigh,
				Confidence: findings.ConfidenceFirm,
				Modes:      []findings.Mode{findings.ModeGray},
				Target:     tgt,
				Evidence: findings.Evidence{
					Note: field + " unescapes to: " + excerpt(unescaped),
				},
				CWE:         "CWE-116",
				Remediation: "Remove Unicode-escaped content from tool metadata.",
				StageStatus: findings.StageCompleted,
			}
			f.ID = f.Fingerprint()
			out = append(out, f)
		}
	}

	return out
}

func extractBase64Candidates(text string) []string {
	const b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	var candidates []string
	words := strings.Fields(text)
	for _, w := range words {
		if len(w) < 12 {
			continue
		}
		ok := true
		for _, c := range w {
			if !strings.ContainsRune(b64chars, c) {
				ok = false
				break
			}
		}
		if ok {
			candidates = append(candidates, w)
		}
	}
	return candidates
}

func matchThreat(decoded string) string {
	lower := strings.ToLower(decoded)
	for _, kw := range encodedThreatWords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return kw
		}
	}
	return ""
}

func unescapeUnicode(s string) string {
	if !strings.Contains(s, "\\u") && !strings.Contains(s, "\\x") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if i+5 < len(s) && s[i] == '\\' && s[i+1] == 'u' {
			hex := s[i+2 : i+6]
			if r, ok := parseHex4(hex); ok {
				b.WriteRune(r)
				i += 6
				continue
			}
		}
		if i+3 < len(s) && s[i] == '\\' && s[i+1] == 'x' {
			hex := s[i+2 : i+4]
			if r, ok := parseHex2(hex); ok {
				b.WriteByte(byte(r))
				i += 4
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func parseHex4(s string) (rune, bool) {
	if len(s) != 4 {
		return 0, false
	}
	var r rune
	for _, c := range s {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	return r, true
}

func parseHex2(s string) (rune, bool) {
	if len(s) != 2 {
		return 0, false
	}
	var r rune
	for _, c := range s {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	return r, true
}
