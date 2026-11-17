package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DialKind identifies the transport the dialer selected.
type DialKind string

const (
	// DialStreamableHTTP is a single-URL POST transport that may reply with
	// JSON or an SSE stream — the modern MCP spec.
	DialStreamableHTTP DialKind = "streamable-http"
	// DialLegacySSE is the two-URL SSE pattern: GET for the event stream, POST
	// to a separate messages endpoint. Used by the majority of deployed MCP
	// servers (SDK 0.x–0.6, FastMCP legacy, early Claude.ai connectors).
	DialLegacySSE DialKind = "legacy-sse"
)

// DialResult describes a successful connection.
type DialResult struct {
	Client *Client
	// URL is the endpoint the dialer actually connected to. Different from the
	// input when path probing was used.
	URL string
	// Kind is the transport the dialer chose.
	Kind DialKind
	// Protocol is the MCP protocol version the server negotiated.
	Protocol string
	// Server is the server's self-reported identity.
	Server Implementation
	// Note is a short, human-readable summary for the scan report (e.g.
	// "streamable-http at /mcp, protocol 2025-06-18, server 'weather/1.2'").
	Note string
	// Initialize is the raw initialize result for callers that want to inspect
	// capabilities or instructions.
	Initialize *InitializeResult
}

// DialOptions configures Dial.
type DialOptions struct {
	// Headers are extra HTTP headers sent on every request (Authorization, etc).
	Headers http.Header
	// HTTPClient overrides the default http.Client. If nil, a sane default is
	// used (reasonable timeout, no redirects on the probe step).
	HTTPClient *http.Client
	// ProbePaths, when non-empty, are URL path suffixes to try if the exact
	// URL fails to connect on either transport. The dialer rewrites the input
	// URL's path with each entry in order. Pass nil to disable probing; pass
	// DefaultProbePaths to try the common conventions.
	ProbePaths []string
	// DialTimeout caps how long the dialer waits for any one candidate URL
	// across both transports before moving on. Defaults to 10s.
	DialTimeout time.Duration
}

// DefaultProbePaths are the conventional paths most MCP servers listen on.
// Order matters: the modern spec encourages `/mcp`; many still live at `/sse`.
var DefaultProbePaths = []string{"/mcp", "/sse", "/"}

// NewTransport is set by the transport package during init via a package-level
// adapter, so the mcp package stays free of a dependency on transport. It
// returns an HTTP streamable transport, a legacy SSE transport, or both.
//
// The actual wiring lives in internal/transport/register.go.
var (
	NewStreamableHTTP func(url string, headers http.Header, client *http.Client) Transport
	NewLegacySSE      func(ctx context.Context, url string, headers http.Header, client *http.Client) (Transport, error)
)

// Dial connects to an MCP endpoint, auto-selecting the transport. It tries
// Streamable HTTP first (one POST, fast to classify) and falls back to legacy
// SSE when the server's response suggests the wrong transport was picked
// (typically HTTP 405, 406, or an empty/non-JSON reply). If the input URL
// fails on both transports and ProbePaths is set, the dialer rewrites the
// path and retries.
//
// Errors are classified: auth failures, DNS failures, and timeouts short-
// circuit and are returned immediately rather than wasting a probe cycle.
func Dial(ctx context.Context, rawURL string, opts DialOptions) (*DialResult, error) {
	if NewStreamableHTTP == nil || NewLegacySSE == nil {
		return nil, errors.New("mcp: transport adapters not registered (import seyon/internal/transport)")
	}
	candidates, err := candidateURLs(rawURL, opts.ProbePaths)
	if err != nil {
		return nil, err
	}
	timeout := opts.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var attempts []dialAttempt
	for _, cand := range candidates {
		// 1) Streamable HTTP
		attempt, res := tryStreamableHTTP(ctx, cand, opts, timeout)
		attempts = append(attempts, attempt)
		if res != nil {
			return res, nil
		}
		if attempt.fatal {
			return nil, attemptsError(attempts)
		}

		// 2) Legacy SSE
		attempt, res = tryLegacySSE(ctx, cand, opts, timeout)
		attempts = append(attempts, attempt)
		if res != nil {
			return res, nil
		}
		if attempt.fatal {
			return nil, attemptsError(attempts)
		}
	}
	return nil, attemptsError(attempts)
}

type dialAttempt struct {
	url   string
	kind  DialKind
	err   error
	fatal bool // short-circuit: no point trying other transports/paths
}

func tryStreamableHTTP(ctx context.Context, rawURL string, opts DialOptions, timeout time.Duration) (dialAttempt, *DialResult) {
	attempt := dialAttempt{url: rawURL, kind: DialStreamableHTTP}
	t := NewStreamableHTTP(rawURL, opts.Headers, opts.HTTPClient)
	c := NewClient(t)
	ictx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	init, err := c.Initialize(ictx)
	if err != nil {
		_ = c.Close()
		attempt.err = err
		attempt.fatal = isFatalDialError(err)
		return attempt, nil
	}
	return attempt, &DialResult{
		Client:     c,
		URL:        rawURL,
		Kind:       DialStreamableHTTP,
		Protocol:   init.ProtocolVersion,
		Server:     init.ServerInfo,
		Note:       dialNote(DialStreamableHTTP, rawURL, init),
		Initialize: init,
	}
}

func tryLegacySSE(ctx context.Context, rawURL string, opts DialOptions, timeout time.Duration) (dialAttempt, *DialResult) {
	attempt := dialAttempt{url: rawURL, kind: DialLegacySSE}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	t, err := NewLegacySSE(dctx, rawURL, opts.Headers, opts.HTTPClient)
	if err != nil {
		attempt.err = err
		attempt.fatal = isFatalDialError(err)
		return attempt, nil
	}
	c := NewClient(t)
	ictx, icancel := context.WithTimeout(ctx, timeout)
	defer icancel()
	init, err := c.Initialize(ictx)
	if err != nil {
		_ = c.Close()
		attempt.err = err
		attempt.fatal = isFatalDialError(err)
		return attempt, nil
	}
	return attempt, &DialResult{
		Client:     c,
		URL:        rawURL,
		Kind:       DialLegacySSE,
		Protocol:   init.ProtocolVersion,
		Server:     init.ServerInfo,
		Note:       dialNote(DialLegacySSE, rawURL, init),
		Initialize: init,
	}
}

// isFatalDialError returns true when the error leaves no chance a different
// transport or path will succeed — e.g. an auth challenge, DNS failure, or
// explicit 404 on the host itself. Transport-mismatch signals (405, 406,
// unexpected content-type) are NOT fatal so the dialer can retry.
func isFatalDialError(err error) bool {
	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		switch httpErr.Code {
		case http.StatusUnauthorized, http.StatusForbidden:
			return true // credentials needed; won't change with transport
		case http.StatusMethodNotAllowed, http.StatusNotAcceptable, http.StatusNotFound,
			http.StatusBadRequest:
			// 400 "Bad Request: Missing session ID" is how the Python MCP SDK
			// streamable HTTP server rejects pre-session discover calls; retrying
			// on legacy SSE often works. 404/405/406 are classic transport
			// mismatch signals.
			return false
		case http.StatusGone, http.StatusInternalServerError, http.StatusBadGateway:
			return false // transient, let the probe cycle decide
		}
		return httpErr.Code < 500
	}
	// Context expiry under the dial timeout should let us keep probing;
	// context cancellation from the caller is fatal.
	if errors.Is(err, context.Canceled) {
		return true
	}
	// Network-level failures that mean the host is unreachable: stop.
	msg := err.Error()
	if strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "connection refused") {
		return true
	}
	return false
}

// candidateURLs builds the ordered list of URLs the dialer will try. The
// input URL always comes first; probe paths rewrite the URL's path.
func candidateURLs(rawURL string, probePaths []string) ([]string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("mcp: parse URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("mcp: URL must be http or https, got %q", u.Scheme)
	}
	out := []string{rawURL}
	seen := map[string]bool{strings.TrimRight(rawURL, "/"): true}
	for _, p := range probePaths {
		cp := *u
		cp.Path = p
		cp.RawQuery = ""
		cp.Fragment = ""
		candidate := cp.String()
		trimmed := strings.TrimRight(candidate, "/")
		if seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		out = append(out, candidate)
	}
	return out, nil
}

func dialNote(kind DialKind, rawURL string, init *InitializeResult) string {
	name := init.ServerInfo.Name
	if name == "" {
		name = "unknown"
	}
	return fmt.Sprintf("%s at %s, protocol %s, server %q",
		kind, rawURL, init.ProtocolVersion, name)
}

// attemptsError aggregates every attempted URL/transport pair into one error
// message so the caller can tell the user exactly what was tried and how each
// attempt failed. Preserves the first unwrappable error for errors.As callers.
func attemptsError(attempts []dialAttempt) error {
	if len(attempts) == 0 {
		return errors.New("mcp: dial: no attempts made")
	}
	var b strings.Builder
	b.WriteString("mcp: dial failed after ")
	fmt.Fprintf(&b, "%d attempt(s):", len(attempts))
	for _, a := range attempts {
		fmt.Fprintf(&b, "\n  - %s %s → %v", a.kind, a.url, a.err)
	}
	return &dialError{msg: b.String(), first: attempts[0].err}
}

type dialError struct {
	msg   string
	first error
}

func (e *dialError) Error() string { return e.msg }
func (e *dialError) Unwrap() error { return e.first }

// CandidateURLsForTest is an unexported-friendly alias exposed for the external
// test package. Not part of the stable API.
func CandidateURLsForTest(raw string, probe []string) ([]string, error) {
	return candidateURLs(raw, probe)
}
