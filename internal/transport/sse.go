package transport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"seyon/internal/mcp"
)

// LegacySSE speaks MCP over the two-URL SSE pattern used by the majority of
// deployed MCP servers (official JS/TS SDK 0.x–0.6, Python FastMCP legacy, and
// anything built against the pre-Streamable-HTTP spec):
//
//  1. Client opens GET <sseURL>. Server responds 200 text/event-stream and
//     holds the connection open.
//  2. Server's first event is `endpoint` carrying the POST URL (often
//     relative, e.g. /messages?sessionId=abc).
//  3. Client POSTs JSON-RPC requests to that URL. Server returns 202 Accepted
//     with no body; the actual response arrives later on the SSE stream as a
//     `message` event.
//  4. Client matches responses to requests by id.
//
// This is a distinct wire format from Streamable HTTP (single-URL POST that
// may optionally reply with an SSE stream). The HTTP transport in httpsse.go
// handles that newer pattern; this one handles the legacy pattern. The dialer
// picks between them.
type LegacySSE struct {
	sseURL  string
	client  *http.Client
	headers http.Header

	// populated after Dial; postURL is the message-POST endpoint the server
	// announces via its first `endpoint` event.
	postURL  string
	endpoint chan struct{} // closed when postURL is set (or dial fails)

	// reader-goroutine state
	cancel     context.CancelFunc
	sseBody    io.Closer
	readerDone chan struct{}

	pendingMu sync.Mutex
	pending   map[string]chan sseResult

	closeOnce sync.Once
	closed    chan struct{}

	// set under pendingMu once the reader hits an unrecoverable error or the
	// server closes the stream. New Call() attempts fail fast with this.
	streamErr error
}

type sseResult struct {
	resp *mcp.Response
	err  error
}

// NewLegacySSE returns an un-dialed transport. Call Dial before use.
func NewLegacySSE(sseURL string, opts ...LegacySSEOption) *LegacySSE {
	t := &LegacySSE{
		sseURL:     sseURL,
		client:     &http.Client{Timeout: 0}, // SSE requires no timeout on the GET
		endpoint:   make(chan struct{}),
		readerDone: make(chan struct{}),
		pending:    map[string]chan sseResult{},
		closed:     make(chan struct{}),
	}
	for _, o := range opts {
		o(t)
	}
	return t
}

// LegacySSEOption configures a LegacySSE transport.
type LegacySSEOption func(*LegacySSE)

// WithSSEHeaders sets headers for both the SSE GET and every POST.
func WithSSEHeaders(h http.Header) LegacySSEOption {
	return func(t *LegacySSE) { t.headers = h }
}

// WithSSEClient overrides the http.Client. The client's Timeout is forced to 0
// for the GET (SSE streams must stay open) but is honored for POSTs via a
// per-POST context timeout.
func WithSSEClient(c *http.Client) LegacySSEOption {
	return func(t *LegacySSE) { t.client = c }
}

// Dial opens the SSE stream, starts the reader goroutine, and blocks until the
// server announces the POST endpoint or the context expires.
func (t *LegacySSE) Dial(ctx context.Context) error {
	readerCtx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel

	req, err := http.NewRequestWithContext(readerCtx, http.MethodGet, t.sseURL, nil)
	if err != nil {
		cancel()
		return fmt.Errorf("sse: build GET: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	for k, vs := range t.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := t.client.Do(req)
	if err != nil {
		cancel()
		return fmt.Errorf("sse: open stream: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = resp.Body.Close()
		cancel()
		return &mcp.HTTPStatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(snippet))}
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/event-stream") {
		_ = resp.Body.Close()
		cancel()
		return fmt.Errorf("sse: unexpected Content-Type %q (want text/event-stream)", ct)
	}
	t.sseBody = resp.Body

	go t.reader(resp.Body)

	// Wait for the endpoint event (or dial-timeout / stream failure).
	select {
	case <-t.endpoint:
		if t.postURL == "" {
			return errors.New("sse: server closed stream before announcing endpoint")
		}
		return nil
	case <-ctx.Done():
		_ = t.Close()
		return fmt.Errorf("sse: endpoint announcement timed out: %w", ctx.Err())
	case <-t.readerDone:
		return t.readError("sse: stream ended before endpoint announcement")
	}
}

// Call sends a JSON-RPC request and waits for the response matching req.ID.
func (t *LegacySSE) Call(ctx context.Context, req mcp.Request) (*mcp.Response, error) {
	key := string(req.ID)
	if key == "" {
		return nil, errors.New("sse: request missing id")
	}
	ch := make(chan sseResult, 1)
	t.pendingMu.Lock()
	if t.streamErr != nil {
		t.pendingMu.Unlock()
		return nil, t.streamErr
	}
	t.pending[key] = ch
	t.pendingMu.Unlock()
	defer func() {
		t.pendingMu.Lock()
		delete(t.pending, key)
		t.pendingMu.Unlock()
	}()

	if err := t.post(ctx, req); err != nil {
		return nil, err
	}
	select {
	case r := <-ch:
		return r.resp, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.readerDone:
		return nil, t.readError("sse: stream closed before response")
	case <-t.closed:
		return nil, errors.New("sse: transport closed")
	}
}

// Notify sends a notification. There is no pending response slot.
func (t *LegacySSE) Notify(ctx context.Context, req mcp.Request) error {
	return t.post(ctx, req)
}

// Close shuts down the SSE stream and makes pending Call() attempts fail fast.
func (t *LegacySSE) Close() error {
	t.closeOnce.Do(func() {
		if t.cancel != nil {
			t.cancel()
		}
		if t.sseBody != nil {
			_ = t.sseBody.Close()
		}
		close(t.closed)
	})
	return nil
}

func (t *LegacySSE) readError(fallback string) error {
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()
	if t.streamErr != nil {
		return t.streamErr
	}
	return errors.New(fallback)
}

func (t *LegacySSE) post(ctx context.Context, req mcp.Request) error {
	if t.postURL == "" {
		return errors.New("sse: post before endpoint negotiated")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("sse: marshal request: %w", err)
	}
	// POSTs should honor the caller's context deadline (unlike the long-lived
	// GET). If the caller did not set one, apply a sane default.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.postURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, vs := range t.headers {
		for _, v := range vs {
			httpReq.Header.Add(k, v)
		}
	}
	// Use a POST-only client so the SSE client's Timeout: 0 does not apply.
	postClient := &http.Client{Timeout: 0, Transport: t.client.Transport}
	resp, err := postClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("sse: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	// Legacy SSE servers answer 202 Accepted; the official SDK also accepts 200.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &mcp.HTTPStatusError{Code: resp.StatusCode}
	}
	return nil
}

// reader parses the SSE stream, dispatches endpoint events and message events.
func (t *LegacySSE) reader(body io.ReadCloser) {
	defer close(t.readerDone)
	defer func() { _ = body.Close() }()

	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)

	var event string
	var data strings.Builder

	flush := func() {
		if data.Len() == 0 && event == "" {
			return
		}
		payload := data.String()
		data.Reset()
		ev := event
		event = ""
		switch ev {
		case "endpoint":
			t.setEndpoint(payload)
		case "", "message":
			t.deliver(payload)
		}
	}

	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, ":") {
			// SSE comment / keep-alive
			continue
		}
		if strings.HasPrefix(line, "event:") {
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if strings.HasPrefix(line, "data:") {
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			continue
		}
		// id:, retry: and anything else — the MCP protocol doesn't depend on
		// them, so ignore.
	}
	flush() // trailing event at EOF

	if err := sc.Err(); err != nil {
		t.setStreamErr(fmt.Errorf("sse: read stream: %w", err))
	} else {
		t.setStreamErr(errors.New("sse: stream closed"))
	}

	// Ensure endpoint channel is closed even if the server never announced one,
	// so Dial() doesn't block forever.
	t.pendingMu.Lock()
	for _, ch := range t.pending {
		select {
		case ch <- sseResult{err: t.streamErr}:
		default:
		}
	}
	t.pendingMu.Unlock()
	t.closeEndpoint()
}

func (t *LegacySSE) setStreamErr(err error) {
	t.pendingMu.Lock()
	if t.streamErr == nil {
		t.streamErr = err
	}
	t.pendingMu.Unlock()
}

func (t *LegacySSE) closeEndpoint() {
	defer func() { _ = recover() }() // close of already-closed channel is a no-op here
	select {
	case <-t.endpoint:
		// already closed
	default:
		close(t.endpoint)
	}
}

// setEndpoint resolves the endpoint URL (relative to the SSE URL's origin if
// needed) and unblocks Dial.
func (t *LegacySSE) setEndpoint(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		t.closeEndpoint()
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.setStreamErr(fmt.Errorf("sse: parse endpoint %q: %w", raw, err))
		t.closeEndpoint()
		return
	}
	if !u.IsAbs() {
		base, baseErr := url.Parse(t.sseURL)
		if baseErr != nil {
			t.setStreamErr(fmt.Errorf("sse: resolve endpoint: %w", baseErr))
			t.closeEndpoint()
			return
		}
		u = base.ResolveReference(u)
	}
	t.postURL = u.String()
	t.closeEndpoint()
}

// deliver parses a message event payload and routes it to the pending Call().
func (t *LegacySSE) deliver(payload string) {
	if strings.TrimSpace(payload) == "" {
		return
	}
	var resp mcp.Response
	if err := json.Unmarshal([]byte(payload), &resp); err != nil {
		// Ignore unparseable payloads; a well-formed server does not send them,
		// and a scanner should not crash on a buggy one.
		return
	}
	key := string(resp.ID)
	if key == "" {
		// Notifications/log messages from the server — not awaited by anyone.
		return
	}
	t.pendingMu.Lock()
	ch, ok := t.pending[key]
	t.pendingMu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- sseResult{resp: &resp}:
	default:
	}
}
