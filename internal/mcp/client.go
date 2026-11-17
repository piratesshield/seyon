package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// maxPages caps pagination per list method, so a server that returns an endless
// stream of cursors cannot hang a scan. Hitting the cap marks the inventory
// incomplete rather than silently truncating.
const maxPages = 1000

// Client speaks MCP over a Transport. It is not safe for concurrent use by
// multiple goroutines; one Client drives one session.
type Client struct {
	t          Transport
	nextID     int
	clientInfo Implementation
	initDone   bool
	initResult *InitializeResult // cached handshake result, so Initialize is idempotent
}

// MarkInitialized records that the handshake has already been performed on
// this client (typically by Dial). Subsequent calls to Initialize return the
// cached result without re-handshaking.
func (c *Client) MarkInitialized(res *InitializeResult) {
	c.initDone = true
	c.initResult = res
}

// discoverModern sends an MCP 2.0 server/discover request. Its _meta envelope
// carries the preferred protocol version plus client identity/capabilities, as
// the official SDK does. A successful response avoids the version-walk that
// legacy initialize() has to do.
func (c *Client) discoverModern(ctx context.Context) (*DiscoverResult, error) {
	params := discoverParams{
		Meta: map[string]interface{}{
			"io.modelcontextprotocol/protocolVersion":    ModernProtocolVersion,
			"io.modelcontextprotocol/clientInfo":         c.clientInfo,
			"io.modelcontextprotocol/clientCapabilities": map[string]interface{}{},
		},
	}
	var res DiscoverResult
	if err := c.call(ctx, "server/discover", params, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// shouldFallbackFromDiscover identifies error shapes where discover is
// unsupported by the server (not a protocol bug). It matches:
//   - -32601 "method not found" (pre-2.0 server, no discover endpoint)
//   - -32602 "Invalid request parameters" (Python MCP 1.x stdio quirk)
//   - -32600 "Bad Request: Missing session ID" (Python MCP 1.x streamable HTTP)
//   - any protocol-version mismatch (server rejects 2026-07-28; initialize()
//     walks the older versions)
//
// Any other error is surfaced so a legitimate failure of a 2.0 server is not
// silently downgraded to initialize().
func shouldFallbackFromDiscover(err error) bool {
	if IsUnsupportedProtocol(err) {
		return true
	}
	var rpc *RPCError
	if !errors.As(err, &rpc) {
		return false
	}
	switch rpc.Code {
	case -32601:
		return true
	case -32602:
		return rpc.Message == "Invalid request parameters"
	case -32600:
		return rpc.Message == "Bad Request: Missing session ID"
	}
	return false
}

// NewClient wraps a transport.
func NewClient(t Transport) *Client {
	return &Client{
		t:          t,
		clientInfo: Implementation{Name: "seyon", Version: "0.1.0"},
	}
}

func (c *Client) id() int { c.nextID++; return c.nextID }

// call sends a request and unmarshals result into out. An RPC error is returned
// as an *RPCError.
func (c *Client) call(ctx context.Context, method string, params, out interface{}) error {
	resp, err := c.t.Call(ctx, newRequest(c.id(), method, params))
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	if out == nil {
		return nil
	}
	if len(resp.Result) == 0 {
		return fmt.Errorf("mcp: empty result for %s", method)
	}
	if err := json.Unmarshal(resp.Result, out); err != nil {
		return fmt.Errorf("mcp: decode %s result: %w", method, err)
	}
	return nil
}

// Initialize performs the handshake and sends notifications/initialized. It
// must be called before any list method.
//
// Protocol-version negotiation: the client first tries ProtocolVersion. If the
// server rejects it with an unsupported-protocol error, Initialize walks the
// SupportedProtocolVersions list. If the server volunteered a list of
// supported versions in the error payload, that list takes precedence (highest
// mutually-supported version wins) — this matches the behavior of the official
// MCP SDK and lets Seyon speak to both older and newer deployments.
func (c *Client) Initialize(ctx context.Context) (*InitializeResult, error) {
	if c.initDone && c.initResult != nil {
		return c.initResult, nil
	}

	// MCP 2.0: try server/discover first. On a supported server it is one
	// round-trip and carries the SupportedVersions list so we skip the
	// version-walk entirely. We only treat specific error shapes as "fall
	// back to initialize": method-not-found (-32601), legacy-stdio invalid-
	// params (-32602 w/ "Invalid request parameters"), or legacy-http
	// missing-session (-32600 w/ "Bad Request: Missing session ID"). Other
	// errors bubble up so a malformed modern discover is not silently
	// downgraded.
	if disc, err := c.discoverModern(ctx); err == nil {
		// A server that doesn't know server/discover may still send a success
		// envelope with an empty body (JSON-RPC catchall). Treat an empty
		// protocolVersion as "not really a modern response" and fall through.
		if disc.ProtocolVersion != "" {
			init := disc.toInitializeResult()
			if err := c.t.Notify(ctx, newNotification("notifications/initialized", nil)); err != nil {
				return nil, fmt.Errorf("mcp: send initialized: %w", err)
			}
			c.initDone = true
			c.initResult = init
			return init, nil
		}
	} else if !shouldFallbackFromDiscover(err) {
		// Non-fallback error: the server tried to speak modern and failed
		// in a way that is not "I don't know this method". Report it.
		return nil, err
	}

	remaining := negotiationOrder(ProtocolVersion)
	var tried []string
	var lastErr error
	for len(remaining) > 0 {
		version := remaining[0]
		remaining = remaining[1:]
		tried = append(tried, version)
		params := initializeParams{
			ProtocolVersion: version,
			Capabilities:    map[string]interface{}{},
			ClientInfo:      c.clientInfo,
		}
		var res InitializeResult
		err := c.call(ctx, "initialize", params, &res)
		if err == nil {
			// Server may still answer with a mismatched version in the result
			// body; in that case fall through to the next candidate only when
			// the version is one we know we cannot speak.
			if res.ProtocolVersion != "" &&
				!knownVersion(res.ProtocolVersion) &&
				res.ProtocolVersion != version {
				lastErr = fmt.Errorf("mcp: server answered with unknown protocol version %q", res.ProtocolVersion)
				continue
			}
			if err := c.t.Notify(ctx, newNotification("notifications/initialized", nil)); err != nil {
				return nil, fmt.Errorf("mcp: send initialized: %w", err)
			}
			c.initDone = true
			c.initResult = &res
			return &res, nil
		}
		lastErr = err
		if !IsUnsupportedProtocol(err) {
			return nil, err
		}
		// Server told us which versions it speaks — restrict future attempts to
		// the intersection (minus what we already tried) and keep the server's
		// priority order.
		if advertised := SupportedVersionsFromError(err); len(advertised) > 0 {
			remaining = intersectFiltering(advertised, SupportedProtocolVersions, tried)
		}
	}
	return nil, &negotiationError{Tried: tried, Last: lastErr}
}

// negotiationOrder returns the ordered list of versions to try, starting with
// the preferred one.
func negotiationOrder(preferred string) []string {
	out := make([]string, 0, len(SupportedProtocolVersions))
	out = append(out, preferred)
	for _, v := range SupportedProtocolVersions {
		if v != preferred {
			out = append(out, v)
		}
	}
	return out
}

func knownVersion(v string) bool {
	for _, k := range SupportedProtocolVersions {
		if k == v {
			return true
		}
	}
	return false
}

// intersectFiltering returns the entries of advertised that are in our
// supported list and have not already been tried. Preserves advertised's
// order so the server's priority wins.
func intersectFiltering(advertised, supported, triedList []string) []string {
	supportedSet := map[string]bool{}
	for _, s := range supported {
		supportedSet[s] = true
	}
	tried := map[string]bool{}
	for _, t := range triedList {
		tried[t] = true
	}
	out := make([]string, 0, len(advertised))
	for _, a := range advertised {
		if supportedSet[a] && !tried[a] {
			out = append(out, a)
		}
	}
	return out
}

// ListTools enumerates all tools, following pagination. The bool return is
// false if the listing was truncated at the page cap.
func (c *Client) ListTools(ctx context.Context) ([]Tool, bool, error) {
	var all []Tool
	cursor := ""
	for page := 0; page < maxPages; page++ {
		var res listToolsResult
		if err := c.call(ctx, "tools/list", listParams{Cursor: cursor}, &res); err != nil {
			return all, false, err
		}
		all = append(all, res.Tools...)
		if res.NextCursor == "" {
			return all, true, nil
		}
		cursor = res.NextCursor
	}
	return all, false, nil
}

// ListResources enumerates all resources, following pagination.
func (c *Client) ListResources(ctx context.Context) ([]Resource, bool, error) {
	var all []Resource
	cursor := ""
	for page := 0; page < maxPages; page++ {
		var res listResourcesResult
		if err := c.call(ctx, "resources/list", listParams{Cursor: cursor}, &res); err != nil {
			return all, false, err
		}
		all = append(all, res.Resources...)
		if res.NextCursor == "" {
			return all, true, nil
		}
		cursor = res.NextCursor
	}
	return all, false, nil
}

// ListPrompts enumerates all prompts, following pagination.
func (c *Client) ListPrompts(ctx context.Context) ([]Prompt, bool, error) {
	var all []Prompt
	cursor := ""
	for page := 0; page < maxPages; page++ {
		var res listPromptsResult
		if err := c.call(ctx, "prompts/list", listParams{Cursor: cursor}, &res); err != nil {
			return all, false, err
		}
		all = append(all, res.Prompts...)
		if res.NextCursor == "" {
			return all, true, nil
		}
		cursor = res.NextCursor
	}
	return all, false, nil
}

// Enumerate initializes the session and lists the full tool, resource, and
// prompt surface. A server that does not declare a capability (resources or
// prompts) is allowed to answer its list method with an error or an empty set;
// enumeration treats a "method not found" as an empty, complete list.
func (c *Client) Enumerate(ctx context.Context) (*Inventory, error) {
	init, err := c.Initialize(ctx)
	if err != nil {
		return nil, err
	}
	inv := &Inventory{
		Server:       init.ServerInfo,
		Protocol:     init.ProtocolVersion,
		Instructions: init.Instructions,
		Complete:     true,
	}

	tools, ok, err := c.ListTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("enumerate tools: %w", err)
	}
	inv.Tools, inv.Complete = tools, inv.Complete && ok

	res, ok, err := c.ListResources(ctx)
	if err != nil && !isMethodNotFound(err) {
		return nil, fmt.Errorf("enumerate resources: %w", err)
	}
	inv.Resources, inv.Complete = res, inv.Complete && (ok || isMethodNotFound(err))

	prompts, ok, err := c.ListPrompts(ctx)
	if err != nil && !isMethodNotFound(err) {
		return nil, fmt.Errorf("enumerate prompts: %w", err)
	}
	inv.Prompts, inv.Complete = prompts, inv.Complete && (ok || isMethodNotFound(err))

	return inv, nil
}

// CallTool invokes a tool by name with the given arguments. It is used only by
// the active prober, which supplies inert canary values; the client itself
// never constructs exploit payloads.
func (c *Client) CallTool(ctx context.Context, name string, args map[string]interface{}) (*CallToolResult, error) {
	var res CallToolResult
	if err := c.call(ctx, "tools/call", callToolParams{Name: name, Arguments: args}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// GetPrompt fetches the rendered message bodies of a prompt template. Args
// should be benign filler strings for each declared argument; the scanner
// only wants to see what the prompt expands to.
func (c *Client) GetPrompt(ctx context.Context, name string, args map[string]string) (*GetPromptResult, error) {
	var res GetPromptResult
	if err := c.call(ctx, "prompts/get", getPromptParams{Name: name, Arguments: args}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ReadResource fetches the content of a resource URI. Returns a result with
// text and/or blob content blocks.
func (c *Client) ReadResource(ctx context.Context, uri string) (*ReadResourceResult, error) {
	var res ReadResourceResult
	if err := c.call(ctx, "resources/read", readResourceParams{URI: uri}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// HTTPStatusError is returned by the HTTP transport when the server answers the
// handshake with a non-2xx status. It preserves the status code and a short
// body snippet so the black-box engine can classify the response (for example,
// 401 authentication-required) instead of treating every refusal as opaque.
type HTTPStatusError struct {
	Code int
	Body string
}

func (e *HTTPStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("http: status %d", e.Code)
	}
	return fmt.Sprintf("http: status %d: %s", e.Code, e.Body)
}

// isMethodNotFound reports whether err is a JSON-RPC "method not found"
// (-32601), including when wrapped.
func isMethodNotFound(err error) bool {
	var rpcErr *RPCError
	if errors.As(err, &rpcErr) {
		return rpcErr.Code == -32601
	}
	return false
}

// Close closes the underlying transport.
func (c *Client) Close() error { return c.t.Close() }
