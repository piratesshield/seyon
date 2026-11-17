package mcp

import "encoding/json"

// ProtocolVersion is the MCP spec revision this client prefers. MCP versions
// its protocol by date; we start here and fall back through
// SupportedProtocolVersions when a server rejects it.
const ProtocolVersion = "2025-06-18"

// Implementation identifies a client or server.
type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// initializeParams is sent by the client to open a session.
type initializeParams struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ClientInfo      Implementation         `json:"clientInfo"`
}

// InitializeResult is the server's response to initialize.
type InitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      Implementation         `json:"serverInfo"`
	Instructions    string                 `json:"instructions,omitempty"`
}

// discoverParams are sent to server/discover in MCP 2.0. The envelope under
// _meta is how modern servers carry the client's version and capabilities
// without polluting the top-level params.
type discoverParams struct {
	Meta map[string]interface{} `json:"_meta,omitempty"`
}

// DiscoverResult is the server's response to server/discover. It mirrors
// InitializeResult but adds supportedVersions so a client can renegotiate
// without relying on error responses.
type DiscoverResult struct {
	ProtocolVersion   string                 `json:"protocolVersion"`
	SupportedVersions []string               `json:"supportedVersions,omitempty"`
	Capabilities      map[string]interface{} `json:"capabilities"`
	ServerInfo        Implementation         `json:"serverInfo"`
	Instructions      string                 `json:"instructions,omitempty"`
}

// toInitializeResult flattens a DiscoverResult into the Initialize shape so
// the rest of the code can treat both the same way.
func (d *DiscoverResult) toInitializeResult() *InitializeResult {
	return &InitializeResult{
		ProtocolVersion: d.ProtocolVersion,
		Capabilities:    d.Capabilities,
		ServerInfo:      d.ServerInfo,
		Instructions:    d.Instructions,
	}
}

// Tool is an MCP tool definition as presented to the agent.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// Resource is an MCP resource definition.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

// PromptArgument describes one argument of a prompt.
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// Prompt is an MCP prompt definition.
type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// paginated params and results. MCP paginates list methods with an opaque
// cursor; a response omits nextCursor when the final page is reached.
type listParams struct {
	Cursor string `json:"cursor,omitempty"`
}

type listToolsResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

type listResourcesResult struct {
	Resources  []Resource `json:"resources"`
	NextCursor string     `json:"nextCursor,omitempty"`
}

type listPromptsResult struct {
	Prompts    []Prompt `json:"prompts"`
	NextCursor string   `json:"nextCursor,omitempty"`
}

// callToolParams invokes a tool. Arguments is an arbitrary JSON object keyed by
// the tool's declared input properties.
type callToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// ToolContent is one block of a tool result. MCP returns an array of typed
// content blocks; Seyon reads the text blocks for its (inert) canary checks.
type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// CallToolResult is the result of tools/call.
type CallToolResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// Text concatenates the text of every text content block.
func (r *CallToolResult) Text() string {
	var b []byte
	for _, c := range r.Content {
		if c.Type == "text" || c.Text != "" {
			if len(b) > 0 {
				b = append(b, '\n')
			}
			b = append(b, c.Text...)
		}
	}
	return string(b)
}

// Inventory is the enumerated surface of a server, plus a record of whether
// enumeration reached the end of every list.
type Inventory struct {
	Server    Implementation `json:"server"`
	Protocol  string         `json:"protocol"`
	Tools     []Tool         `json:"tools"`
	Resources []Resource     `json:"resources"`
	Prompts   []Prompt       `json:"prompts"`
	// Instructions is the server-level directive text from the initialize
	// result. Clients insert this into the agent's system prompt, so it is a
	// prompt-injection surface worth scanning the same way we scan tool
	// descriptions. Empty when the server did not advertise one.
	Instructions string `json:"instructions,omitempty"`
	// Complete is false if any list was truncated (e.g. pagination hit a cap or
	// errored). A partial inventory must never be reported as "clean".
	Complete bool `json:"complete"`
}

// getPromptParams is sent to prompts/get. Arguments mirrors the shape clients
// use when rendering: a flat {name → string value} map.
type getPromptParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

// PromptMessageContent is one content block of a prompt message. MCP messages
// are arrays of typed content; the scanner reads text blocks.
type PromptMessageContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// PromptMessage is one message turn in a rendered prompt template.
type PromptMessage struct {
	Role    string                 `json:"role"`
	Content []PromptMessageContent `json:"content"`
}

// GetPromptResult is the server's response to prompts/get. It carries the
// rendered message bodies that the agent will see.
type GetPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages,omitempty"`
}

// Text concatenates every text block across every message, separated by
// newlines. Empty content blocks are skipped. This is the string the
// prompt-content detectors analyze.
func (r *GetPromptResult) Text() string {
	var parts []string
	for _, m := range r.Messages {
		for _, c := range m.Content {
			if c.Type == "text" && c.Text != "" {
				parts = append(parts, c.Text)
			} else if c.Type == "" && c.Text != "" {
				// some servers omit the type field but still send text
				parts = append(parts, c.Text)
			}
		}
	}
	return joinNonEmpty(parts, "\n")
}

// readResourceParams is sent to resources/read.
type readResourceParams struct {
	URI string `json:"uri"`
}

// ResourceContent is one block of a resource/read result. A content block
// carries either text or a base64 blob; the scanner reads text.
type ResourceContent struct {
	URI      string `json:"uri,omitempty"`
	MIMEType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

// ReadResourceResult is the server's response to resources/read.
type ReadResourceResult struct {
	Contents []ResourceContent `json:"contents,omitempty"`
}

// TextWithMime returns the concatenated text from every text block, and the
// best-guess MIME type (the first non-empty one, or "" if every block is
// binary). The returned "truncated" flag indicates the caller should treat
// the string as incomplete when it exceeds the given max.
func (r *ReadResourceResult) TextWithMime(max int) (text, mime string, truncated bool) {
	var parts []string
	seen := 0
	for _, c := range r.Contents {
		if c.Text == "" {
			continue
		}
		if mime == "" && c.MIMEType != "" {
			mime = c.MIMEType
		}
		room := max - seen
		if room <= 0 {
			truncated = true
			break
		}
		piece := c.Text
		if len(piece) > room {
			piece = piece[:room]
			truncated = true
		}
		parts = append(parts, piece)
		seen += len(piece)
	}
	text = joinNonEmpty(parts, "\n")
	return text, mime, truncated
}

func joinNonEmpty(parts []string, sep string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			out += sep
		}
		out += p
	}
	return out
}
