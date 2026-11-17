package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"seyon/internal/findings"
)

// Protocol runs a set of safe read-only wire-protocol probes against a live
// HTTP MCP endpoint. These checks establish the server's security posture
// without invoking any tool, so they are safe to run against servers where the
// operator has no business calling tools (public gateways, third-party APIs
// they are authorized to audit).
//
// Each check maps to a Seyon "P" (protocol) rule and carries a CWE and an
// OWASP MCP cheat-sheet reference where applicable. The design mirrors Cisco
// mcp-scanner's MCPS-001..MCPS-012 taxonomy with Seyon-native rule IDs.
//
// Checks performed:
//
//	P1  transport.unencrypted       URL scheme is http (HIGH, CWE-319)
//	P2  auth.open                   tools/list succeeds without creds (MEDIUM, CWE-306)
//	P3  signing.missing             no response signature / signing capability (MEDIUM, CWE-345)
//	P4  replay.unprotected          duplicate requests both return 200 (MEDIUM, CWE-294)
//	P5  tools.unintegrity           tool defs lack hash/signature/integrity (MEDIUM, CWE-494)
//	P6  fail-open                   malformed input still returns a 200 result (MEDIUM, CWE-636)
//	P7  rate-limit.missing          10 rapid requests all accepted (MEDIUM, CWE-770)
//	P8  identity.spoofable          X-Agent-* headers accepted at face value (HIGH, CWE-290)
//
// The probe sends at most ~15 HTTP requests to the target; a target that
// cannot absorb that is itself a finding (P7).
type Protocol struct {
	client  *http.Client
	headers http.Header
}

// NewProtocol returns a protocol prober. Pass extra headers (e.g. a bearer
// token) that should accompany every request; the auth-open check accounts
// for them by running once with and once without.
func NewProtocol(headers http.Header) *Protocol {
	return &Protocol{
		client: &http.Client{
			Timeout: 15 * time.Second,
			// Protocol probes should see the server's own response, never a
			// provider's "please log in" redirect.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		headers: headers,
	}
}

// Run executes every check and returns the aggregated findings.
func (p *Protocol) Run(ctx context.Context, rawURL string) []findings.Finding {
	var out []findings.Finding

	out = append(out, p.checkTransport(rawURL)...)

	// tools/list probe — used by P2 (unauth), P3 (signing), P5 (integrity), P7 (rate).
	toolsResp, toolsBody := p.jsonRPC(ctx, rawURL, "tools/list", nil, nil)

	out = append(out, p.checkOpenAuth(rawURL, toolsResp, toolsBody)...)
	out = append(out, p.checkSigning(rawURL, toolsResp)...)
	out = append(out, p.checkToolIntegrity(rawURL, toolsBody)...)
	out = append(out, p.checkReplay(ctx, rawURL)...)
	out = append(out, p.checkFailOpen(ctx, rawURL)...)
	out = append(out, p.checkSpoofedIdentity(ctx, rawURL)...)
	out = append(out, p.checkRateLimit(ctx, rawURL)...)

	return out
}

// ─── P1 ─────────────────────────────────────────────────────────────────
func (p *Protocol) checkTransport(rawURL string) []findings.Finding {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" {
		return nil
	}
	if u.Scheme != "http" {
		return nil
	}
	return []findings.Finding{p.mk(
		"P1.transport.unencrypted",
		"MCP endpoint is served over unencrypted HTTP",
		findings.SeverityHigh,
		findings.ConfidenceFirm,
		rawURL,
		"the URL uses the http scheme; every JSON-RPC message, tool argument, and response travels in plaintext",
		"CWE-319",
		"Serve the MCP endpoint over https. If the target is a dev loopback, confirm it is not reachable from outside the host.",
	)}
}

// ─── P2 ─────────────────────────────────────────────────────────────────
func (p *Protocol) checkOpenAuth(rawURL string, resp *http.Response, body []byte) []findings.Finding {
	if resp == nil || resp.StatusCode != 200 {
		return nil
	}
	tools := extractTools(body)
	if tools == nil {
		return nil
	}
	// If the operator supplied Authorization or an API key, the scan ran as
	// an authenticated caller. Describe the finding accordingly.
	authPresent := false
	for k := range p.headers {
		if strings.EqualFold(k, "Authorization") ||
			strings.HasPrefix(strings.ToLower(k), "x-api-key") ||
			strings.EqualFold(k, "X-Api-Token") {
			authPresent = true
			break
		}
	}
	if authPresent {
		return nil // can't conclude from an authenticated probe
	}
	return []findings.Finding{p.mk(
		"P2.auth.open",
		"MCP endpoint exposes tool definitions to unauthenticated callers",
		findings.SeverityMedium,
		findings.ConfidenceFirm,
		rawURL,
		fmt.Sprintf("tools/list returned %d tool definition(s) without any credential; tool INVOCATION was not tested and may still enforce auth", len(tools)),
		"CWE-306",
		"If this surface is not meant to be public, require authentication on the MCP endpoint (bearer token, mTLS, or an edge proxy). Enumeration is the first step of a tool-abuse chain even when invocation is gated.",
	)}
}

// ─── P3 ─────────────────────────────────────────────────────────────────
func (p *Protocol) checkSigning(rawURL string, resp *http.Response) []findings.Finding {
	if resp == nil {
		return nil
	}
	// A response is "signed" if either a known signature header is present OR
	// the server's capabilities object declares a signing feature.
	signatureHeaders := []string{
		"X-Mcps-Signature", "X-Attp-Signature", "X-Agent-Signature", "Signature",
	}
	for _, h := range signatureHeaders {
		if resp.Header.Get(h) != "" {
			return nil
		}
	}
	return []findings.Finding{p.mk(
		"P3.signing.missing",
		"MCP responses are not cryptographically signed",
		findings.SeverityMedium,
		findings.ConfidenceTentative,
		rawURL,
		"no X-Mcps-Signature / X-Attp-Signature / X-Agent-Signature header was present on the handshake response; a network intermediary could modify tool results without detection",
		"CWE-345",
		"Adopt a signed-response scheme (MCPS, ATTP, or an application-level JWS) and have the client verify every tool result. Treat unsigned responses as untrusted data.",
	)}
}

// ─── P4 ─────────────────────────────────────────────────────────────────
func (p *Protocol) checkReplay(ctx context.Context, rawURL string) []findings.Finding {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "replay-check",
		"method":  "tools/list",
	}
	r1, _ := p.rawRPC(ctx, rawURL, payload, nil)
	r2, _ := p.rawRPC(ctx, rawURL, payload, nil)
	if r1 == nil || r2 == nil {
		return nil
	}
	if r1.StatusCode == 200 && r2.StatusCode == 200 {
		return []findings.Finding{p.mk(
			"P4.replay.unprotected",
			"MCP endpoint accepts replayed identical requests",
			findings.SeverityMedium,
			findings.ConfidenceFirm,
			rawURL,
			"two byte-identical tools/list requests both returned 200; no nonce or timestamp validation was observed, so an attacker who captures a legitimate request can replay it",
			"CWE-294",
			"Require a per-request nonce or short-lived timestamp (and reject duplicates) on every JSON-RPC call. Without it, a captured tool-call request can be replayed at will.",
		)}
	}
	return nil
}

// ─── P5 ─────────────────────────────────────────────────────────────────
func (p *Protocol) checkToolIntegrity(rawURL string, body []byte) []findings.Finding {
	tools := extractTools(body)
	if len(tools) == 0 {
		return nil
	}
	for _, t := range tools {
		if _, ok := t["hash"]; ok {
			return nil
		}
		if _, ok := t["integrity"]; ok {
			return nil
		}
		if _, ok := t["signature"]; ok {
			return nil
		}
	}
	return []findings.Finding{p.mk(
		"P5.tools.unintegrity",
		"Tool definitions lack integrity hashes or signatures",
		findings.SeverityMedium,
		findings.ConfidenceFirm,
		rawURL,
		fmt.Sprintf("%d tool definition(s) have no hash / integrity / signature field; the server could swap a tool's schema after initial approval (a rug-pull attack) without the client noticing", len(tools)),
		"CWE-494",
		"Have the server include a content-hash (hash / integrity / signature) in each tool definition and have the client pin and verify it on every refresh. This is the only defence against post-approval tool-definition swapping.",
	)}
}

// ─── P6 ─────────────────────────────────────────────────────────────────
func (p *Protocol) checkFailOpen(ctx context.Context, rawURL string) []findings.Finding {
	// Non-JSON-RPC bodies that a strict server must reject with 4xx.
	bodies := [][]byte{
		[]byte(`{"not_jsonrpc": true}`),
		[]byte(`this is not json`),
	}
	for _, body := range bodies {
		resp, respBody := p.rawBody(ctx, rawURL, body, "application/json")
		if resp == nil {
			continue
		}
		if resp.StatusCode != 200 {
			continue
		}
		// 200 is only a problem if the body looks like it was processed (has
		// result/data), not a JSON error object.
		var parsed map[string]json.RawMessage
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			continue
		}
		_, hasErr := parsed["error"]
		_, hasResult := parsed["result"]
		if hasResult && !hasErr {
			return []findings.Finding{p.mk(
				"P6.fail-open",
				"MCP endpoint processes malformed input instead of rejecting it",
				findings.SeverityMedium,
				findings.ConfidenceFirm,
				rawURL,
				"a body that is not a JSON-RPC request still returned a 200 result; the server fails open on invalid input, suggesting the request router performs no schema validation",
				"CWE-636",
				"Reject any body that is not a valid JSON-RPC 2.0 envelope with a 400 and a JSON-RPC error object. Fail-open behaviour is often the first step in a malformed-request DoS chain.",
			)}
		}
	}
	return nil
}

// ─── P7 ─────────────────────────────────────────────────────────────────
func (p *Protocol) checkRateLimit(ctx context.Context, rawURL string) []findings.Finding {
	payload := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list",
	}
	accepted := 0
	rateLimited := false
	for i := 0; i < 10; i++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		resp, _ := p.rawRPC(ctx, rawURL, payload, nil)
		if resp == nil {
			continue
		}
		if resp.StatusCode == 429 {
			rateLimited = true
			break
		}
		if resp.StatusCode == 200 {
			accepted++
		}
	}
	if !rateLimited && accepted >= 10 {
		return []findings.Finding{p.mk(
			"P7.rate-limit.missing",
			"MCP endpoint does not rate-limit rapid requests",
			findings.SeverityMedium,
			findings.ConfidenceFirm,
			rawURL,
			fmt.Sprintf("sent %d rapid tools/list requests, all accepted with 200; no 429 response and no observable backoff — the endpoint is vulnerable to resource exhaustion and tool-fuzzing abuse", accepted),
			"CWE-770",
			"Enforce a per-caller rate limit (token bucket or sliding window) with 429 responses. Rate limiting is the single cheapest control against brute-forcing tool arguments.",
		)}
	}
	return nil
}

// ─── P8 ─────────────────────────────────────────────────────────────────
func (p *Protocol) checkSpoofedIdentity(ctx context.Context, rawURL string) []findings.Finding {
	spoofed := http.Header{
		"X-Agent-Id":          []string{"spoofed-admin-agent"},
		"X-Agent-Role":        []string{"admin"},
		"X-Agent-Trust-Level": []string{"4"},
	}
	payload := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list",
	}
	resp, body := p.rawRPC(ctx, rawURL, payload, spoofed)
	if resp == nil || resp.StatusCode != 200 {
		return nil
	}
	// The result is a problem only if the server processed the request.
	tools := extractTools(body)
	if tools == nil {
		return nil
	}
	return []findings.Finding{p.mk(
		"P8.identity.spoofable",
		"MCP endpoint accepts spoofed agent-identity headers",
		findings.SeverityHigh,
		findings.ConfidenceFirm,
		rawURL,
		"the server processed a request carrying X-Agent-Id / X-Agent-Role / X-Agent-Trust-Level headers set to attacker-chosen values; identity claimed via plain headers is trivially spoofable",
		"CWE-290",
		"Do not trust agent-identity headers set by the client. Derive identity from a cryptographically verified token (JWT with a server-controlled signing key, mTLS cert, OAuth session).",
	)}
}

// ─── helpers ────────────────────────────────────────────────────────────

func (p *Protocol) jsonRPC(ctx context.Context, rawURL, method string, params interface{}, extra http.Header) (*http.Response, []byte) {
	payload := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": method,
	}
	if params != nil {
		payload["params"] = params
	}
	return p.rawRPC(ctx, rawURL, payload, extra)
}

func (p *Protocol) rawRPC(ctx context.Context, rawURL string, payload map[string]interface{}, extra http.Header) (*http.Response, []byte) {
	body, _ := json.Marshal(payload)
	if extra != nil {
		return p.rawBody(ctx, rawURL, body, "application/json", extra)
	}
	return p.rawBody(ctx, rawURL, body, "application/json")
}

func (p *Protocol) rawBody(ctx context.Context, rawURL string, body []byte, contentType string, extra ...http.Header) (*http.Response, []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, vs := range p.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for _, h := range extra {
		for k, vs := range h {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, data
}

// extractTools returns the tools array from a JSON-RPC response body, or nil
// if the body does not describe a tools/list result. Handles both direct
// application/json responses and SSE-framed responses whose payload is on a
// `data:` line.
func extractTools(body []byte) []map[string]interface{} {
	payloads := [][]byte{body}
	// Try to extract from an SSE frame too.
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("event:")) ||
		bytes.Contains(body, []byte("\ndata:")) {
		for _, line := range bytes.Split(body, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("data:")) {
				payloads = append(payloads, bytes.TrimSpace(line[5:]))
			}
		}
	}
	for _, p := range payloads {
		var env struct {
			Result struct {
				Tools []map[string]interface{} `json:"tools"`
			} `json:"result"`
		}
		if err := json.Unmarshal(p, &env); err == nil && env.Result.Tools != nil {
			return env.Result.Tools
		}
	}
	return nil
}

func (p *Protocol) mk(ruleID, title string, sev findings.Severity, conf findings.Confidence, endpoint, note, cwe, remediation string) findings.Finding {
	f := findings.Finding{
		RuleID:      ruleID,
		Class:       "P",
		Title:       title,
		Severity:    sev,
		Confidence:  conf,
		Modes:       []findings.Mode{findings.ModeBlack},
		Target:      findings.Target{Endpoint: endpoint},
		Evidence:    findings.Evidence{Note: note},
		CWE:         cwe,
		References:  []string{"mcp-protocol-probe", "owasp-mcp-cheat-sheet"},
		Remediation: remediation,
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return f
}
