// Command refserver is a safe reference MCP server used by Seyon's test lab and
// eval harness. It speaks MCP over stdio (newline-delimited JSON-RPC 2.0) and
// serves a small, static surface — several tools across two pages, one
// resource, and one prompt. It executes nothing and has no side effects; it
// exists so the scanner can be exercised against a known-good target.
package main

import (
	"bufio"
	"encoding/json"
	"os"
)

const protocolVersion = "2025-06-18"

// pageSize forces tools/list to paginate, so the client's pagination is tested.
const pageSize = 2

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

var tools = []tool{
	{Name: "echo", Description: "Echo back the provided text.", InputSchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string","maxLength":1000}},"required":["text"]}`)},
	{Name: "add", Description: "Add two integers and return the sum.", InputSchema: json.RawMessage(`{"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"}},"required":["a","b"]}`)},
	{Name: "now", Description: "Return the current server time in RFC 3339.", InputSchema: json.RawMessage(`{"type":"object","properties":{}}`)},
}

var resources = []map[string]string{
	{"uri": "file:///readme", "name": "readme", "description": "Server documentation.", "mimeType": "text/markdown"},
}

var prompts = []map[string]interface{}{
	{"name": "greeting", "description": "A friendly greeting.", "arguments": []map[string]interface{}{{"name": "name", "description": "who to greet", "required": true}}},
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	enc := json.NewEncoder(os.Stdout)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		// Notifications (no id) are acknowledged by producing no output.
		if len(req.ID) == 0 {
			continue
		}
		resp := handle(req)
		_ = enc.Encode(resp) // Encoder appends a newline, giving stdio framing.
	}
}

func handle(req request) response {
	base := response{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		base.Result = map[string]interface{}{
			"protocolVersion": protocolVersion,
			"capabilities": map[string]interface{}{
				"tools":     map[string]interface{}{},
				"resources": map[string]interface{}{},
				"prompts":   map[string]interface{}{},
			},
			"serverInfo": map[string]string{"name": "seyon-refserver", "version": "0.1.0"},
		}
	case "tools/list":
		page, next := paginateTools(cursorOf(req.Params))
		out := map[string]interface{}{"tools": page}
		if next != "" {
			out["nextCursor"] = next
		}
		base.Result = out
	case "resources/list":
		base.Result = map[string]interface{}{"resources": resources}
	case "prompts/list":
		base.Result = map[string]interface{}{"prompts": prompts}
	default:
		base.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
	return base
}

func cursorOf(params json.RawMessage) string {
	if len(params) == 0 {
		return ""
	}
	var p struct {
		Cursor string `json:"cursor"`
	}
	_ = json.Unmarshal(params, &p)
	return p.Cursor
}

// paginateTools returns the page beginning at cursor and the next cursor ("" at
// the end). The cursor is simply the next index, encoded as text.
func paginateTools(cursor string) ([]tool, string) {
	start := 0
	if cursor != "" {
		// cursor is "<index>"; tolerate junk by resetting to 0.
		n := 0
		for _, c := range cursor {
			if c < '0' || c > '9' {
				n = 0
				break
			}
			n = n*10 + int(c-'0')
		}
		start = n
	}
	if start >= len(tools) {
		return nil, ""
	}
	end := start + pageSize
	if end >= len(tools) {
		return tools[start:], ""
	}
	return tools[start:end], itoa(end)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
