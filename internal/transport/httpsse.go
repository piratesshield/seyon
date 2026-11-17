package transport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"seyon/internal/mcp"
)

// HTTP speaks MCP over the Streamable HTTP transport. A single POST carries one
// JSON-RPC message; the server may answer with either a JSON response
// (application/json) or an SSE stream (text/event-stream) carrying one or more
// messages. The client is pinned to a protocol revision via the
// MCP-Protocol-Version header and carries any negotiated session id.
type HTTP struct {
	url     string
	client  *http.Client
	session string
	headers http.Header
}

// HTTPOption configures an HTTP transport.
type HTTPOption func(*HTTP)

// WithHTTPClient overrides the default http.Client (e.g. for tests or to apply
// the sandbox egress policy).
func WithHTTPClient(c *http.Client) HTTPOption {
	return func(h *HTTP) { h.client = c }
}

// WithHeaders attaches extra HTTP headers (e.g. Authorization) to every request.
// They are applied after the transport's own headers, so a caller may also
// override defaults. Used to scan MCP servers that require authentication with
// a token the caller is authorized to use.
func WithHeaders(hdr http.Header) HTTPOption {
	return func(h *HTTP) { h.headers = hdr }
}

// NewHTTP returns a Streamable HTTP transport for the given endpoint URL.
func NewHTTP(url string, opts ...HTTPOption) *HTTP {
	h := &HTTP{
		url:    url,
		client: &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

func (h *HTTP) post(ctx context.Context, req mcp.Request) (*http.Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("http: marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	httpReq.Header.Set("MCP-Protocol-Version", mcp.ProtocolVersion)
	if h.session != "" {
		httpReq.Header.Set("Mcp-Session-Id", h.session)
	}
	// Caller-supplied headers (e.g. Authorization) are applied last so they can
	// add to or override the defaults above.
	for k, vs := range h.headers {
		httpReq.Header.Del(k)
		for _, v := range vs {
			httpReq.Header.Add(k, v)
		}
	}
	return h.client.Do(httpReq)
}

// Call sends req and returns the response whose id matches.
func (h *HTTP) Call(ctx context.Context, req mcp.Request) (*mcp.Response, error) {
	resp, err := h.post(ctx, req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Capture the session id first — some servers set it on the handshake
	// response even when they reject the request (e.g. 400 "Missing session ID"
	// where the server also tells us the id to use on the retry).
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		h.session = sid
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, &mcp.HTTPStatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(snippet))}
	}

	ct := resp.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "text/event-stream"):
		return matchFromSSE(resp.Body, req.ID)
	default:
		var out mcp.Response
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, fmt.Errorf("http: decode json response: %w", err)
		}
		return &out, nil
	}
}

// Notify sends a notification. A well-behaved server returns 202 Accepted with
// no body; any 2xx is accepted.
func (h *HTTP) Notify(ctx context.Context, req mcp.Request) error {
	resp, err := h.post(ctx, req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http: notify status %d", resp.StatusCode)
	}
	return nil
}

// Close is a no-op for the stateless HTTP transport.
func (h *HTTP) Close() error { return nil }

// matchFromSSE reads an SSE stream and returns the first JSON-RPC message whose
// id matches want. SSE events are separated by a blank line; each event's
// payload is the concatenation of its data: fields.
func matchFromSSE(r io.Reader, want json.RawMessage) (*mcp.Response, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	var data strings.Builder
	flush := func() (*mcp.Response, bool) {
		if data.Len() == 0 {
			return nil, false
		}
		payload := data.String()
		data.Reset()
		var resp mcp.Response
		if err := json.Unmarshal([]byte(payload), &resp); err != nil {
			return nil, false
		}
		if len(resp.ID) != 0 && string(resp.ID) == string(want) {
			return &resp, true
		}
		return nil, false
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" { // event boundary
			if resp, ok := flush(); ok {
				return resp, nil
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
		// field lines other than data: (event:, id:, retry:) are ignored
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("http: read sse: %w", err)
	}
	if resp, ok := flush(); ok {
		return resp, nil
	}
	return nil, fmt.Errorf("http: no matching response in sse stream")
}
