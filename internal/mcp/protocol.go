package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// SupportedProtocolVersions is the ordered list of MCP spec revisions this
// client speaks, newest first. On an UNSUPPORTED_PROTOCOL_VERSION response, the
// client walks the list and retries with the next-oldest version.
//
// References:
//   - 2026-07-28: MCP 2.0, server/discover handshake, new _meta envelope
//   - 2025-11-25: pre-2.0 revision used by some early 2.0 SDKs
//   - 2025-06-18: Streamable HTTP, elicitation, structuredContent
//   - 2025-03-26: prior stable revision, widely deployed
//   - 2024-11-05: initial stable spec, still common in older servers
var SupportedProtocolVersions = []string{
	"2026-07-28",
	"2025-11-25",
	"2025-06-18",
	"2025-03-26",
	"2024-11-05",
}

// ModernProtocolVersion is the newest MCP revision that supports the
// server/discover handshake (MCP 2.0).
const ModernProtocolVersion = "2026-07-28"

// IsUnsupportedProtocol reports whether err looks like the server rejecting our
// protocolVersion. MCP spec servers answer with a JSON-RPC error whose message
// typically names "protocol version" or "unsupported", but implementations vary
// — some return -32602 (invalid params), some -32600 (invalid request), and a
// few return a 200 with an InitializeResult containing an unexpected version.
// The check is defensive: match on code OR on a message substring.
func IsUnsupportedProtocol(err error) bool {
	if err == nil {
		return false
	}
	var rpc *RPCError
	if errors.As(err, &rpc) {
		if rpc.Code == -32602 || rpc.Code == -32600 {
			msg := strings.ToLower(rpc.Message)
			if strings.Contains(msg, "protocol") &&
				(strings.Contains(msg, "version") || strings.Contains(msg, "unsupported")) {
				return true
			}
			// Some servers include supported versions in data; if data is a list
			// of version strings we treat the error as a protocol mismatch.
			if hasVersionDataList(rpc.Data) {
				return true
			}
		}
	}
	return false
}

// SupportedVersionsFromError extracts a server-advertised supported-version
// list from an RPC error's data field. Returns nil when the server did not
// include one.
func SupportedVersionsFromError(err error) []string {
	var rpc *RPCError
	if !errors.As(err, &rpc) {
		return nil
	}
	return versionListFromRaw(rpc.Data)
}

func hasVersionDataList(data json.RawMessage) bool {
	return len(versionListFromRaw(data)) > 0
}

// versionListFromRaw tries two shapes a server may use to carry supported
// versions: a bare array ["2025-06-18", ...] or an object with a known key.
func versionListFromRaw(data json.RawMessage) []string {
	if len(data) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		return filterVersions(arr)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err == nil {
		for _, key := range []string{"supported", "supportedVersions", "supported_versions", "versions"} {
			if raw, ok := obj[key]; ok {
				var list []string
				if err := json.Unmarshal(raw, &list); err == nil {
					if v := filterVersions(list); len(v) > 0 {
						return v
					}
				}
			}
		}
	}
	return nil
}

// filterVersions returns only strings that look like an MCP version (YYYY-MM-DD),
// so garbage in the error doesn't confuse our negotiation.
func filterVersions(in []string) []string {
	out := in[:0:0]
	for _, v := range in {
		if looksLikeMCPVersion(v) {
			out = append(out, v)
		}
	}
	return out
}

func looksLikeMCPVersion(s string) bool {
	if len(s) != 10 {
		return false
	}
	if s[4] != '-' || s[7] != '-' {
		return false
	}
	for i, r := range s {
		if i == 4 || i == 7 {
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// negotiationError wraps the final error when every version has been tried, so
// the caller can show the user both the versions attempted and the server's
// last response.
type negotiationError struct {
	Tried []string
	Last  error
}

func (e *negotiationError) Error() string {
	return fmt.Sprintf("mcp: no mutually supported protocol version (tried %s): %v",
		strings.Join(e.Tried, ", "), e.Last)
}

func (e *negotiationError) Unwrap() error { return e.Last }
