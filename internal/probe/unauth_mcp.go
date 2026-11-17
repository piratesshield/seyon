package probe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"seyon/internal/findings"
)

// RunMCPSpecific runs the MCP-specific unauthenticated checks that are NOT
// generic web-security hygiene — they look for leaks and misconfigurations
// specific to the MCP ecosystem and its common gateways.
//
// Checks performed:
//
//	U21 mcp.transport-enum       alternate transport paths on the same origin
//	U22 mcp.legacy-manifest      ChatGPT-era plugin manifest still served
//	U23 mcp.version-fuzz         server accepts arbitrary Protocol-Version values
//	U24 mcp.leak-in-error        401/403 body enumerates tools/methods/caps
//	U25 oauth.open-redirect      authorization_endpoint accepts attacker redirect_uri
//	U26 jwks.*                   weak RSA/EC key sizes, duplicate kids
//	U27 waf.bypass               X-Original-URL / X-Rewrite-URL / X-Forwarded-Host bypasses
//	U28 auth.rate-limit          no 429 after 15 bad-token attempts
//
// Runs after the generic Unauth checks so findings cross-reference discovered
// OAuth metadata (U12 → U25, U26) without re-fetching discovery documents.
func (u *Unauth) RunMCPSpecific(ctx context.Context, rawURL string) []findings.Finding {
	target, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	var out []findings.Finding
	out = append(out, u.checkTransportEnum(ctx, target)...)
	out = append(out, u.checkLegacyManifest(ctx, target)...)
	out = append(out, u.checkVersionFuzz(ctx, rawURL)...)
	out = append(out, u.checkToolLeakInError(ctx, rawURL)...)
	out = append(out, u.checkOAuthOpenRedirect(ctx, target)...)
	out = append(out, u.checkJWKS(ctx, target)...)
	out = append(out, u.checkWAFBypass(ctx, rawURL)...)
	out = append(out, u.checkAuthRateLimit(ctx, rawURL)...)
	return out
}

// ── U21: transport enumeration ─────────────────────────────────────────

// Known MCP transport paths. A provider that serves on `/mcp` sometimes also
// has a forgotten `/sse` or `/v1/mcp` from a prior deployment — those stale
// surfaces often have weaker posture than the documented one.
var mcpTransportPaths = []string{
	"/mcp", "/sse", "/messages", "/rpc",
	"/api/mcp", "/v1/mcp", "/v2/mcp",
	"/agent/mcp", "/agents/mcp",
	"/connector/mcp", "/mcp/sse", "/mcp/messages",
}

func (u *Unauth) checkTransportEnum(ctx context.Context, target *url.URL) []findings.Finding {
	origin := target.Scheme + "://" + target.Host
	current := strings.TrimRight(target.Path, "/")
	var alive []string
	for _, p := range mcpTransportPaths {
		if strings.TrimRight(p, "/") == current {
			continue // the user's input URL
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+p, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("User-Agent", "seyon-unauth-audit/1.0")
		resp, err := u.client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		// 200/202/400/401/405 all indicate SOMETHING is listening that at
		// least knows the request shape. 404 means nothing is there.
		if resp.StatusCode == 404 || resp.StatusCode == 410 {
			continue
		}
		alive = append(alive, fmt.Sprintf("%s → %d", p, resp.StatusCode))
	}
	if len(alive) == 0 {
		return nil
	}
	return []findings.Finding{u.mk(
		"U21.mcp.transport-enum",
		"Multiple MCP transport paths respond on the same origin",
		findings.SeverityMedium, findings.ConfidenceFirm,
		origin,
		fmt.Sprintf("found %d alternate MCP endpoint(s) besides the one scanned: %s. Stale transports often have weaker auth or outdated protocol handling.", len(alive), strings.Join(alive, ", ")),
		"CWE-200",
		"Audit each live transport path. Decommission the stale ones at the reverse proxy — a forgotten /sse often outlives the /mcp it was replaced with and keeps the same security debt.",
	)}
}

// ── U22: legacy plugin manifest ────────────────────────────────────────

var legacyManifestPaths = []string{
	"/.well-known/ai-plugin.json",
	"/.well-known/mcp.json",
	"/.well-known/agent.json",
	"/openapi.json",
	"/openapi.yaml",
	"/manifest.json",
	"/ai-plugin.json",
}

func (u *Unauth) checkLegacyManifest(ctx context.Context, target *url.URL) []findings.Finding {
	origin := target.Scheme + "://" + target.Host
	var out []findings.Finding
	for _, p := range legacyManifestPaths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+p, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json, text/yaml, */*")
		resp, err := u.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || len(body) < 20 {
			continue
		}
		// Avoid false positives: an SPA that serves index.html for everything
		// will return HTML here. Require the content to look structured.
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if !strings.Contains(ct, "json") && !strings.Contains(ct, "yaml") &&
			!bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) &&
			!bytes.HasPrefix(bytes.TrimSpace(body), []byte("openapi:")) {
			continue
		}
		severity := findings.SeverityMedium
		// ai-plugin.json gives attacker the full tool surface — highest value.
		if strings.Contains(p, "ai-plugin") || strings.Contains(p, "mcp.json") {
			severity = findings.SeverityHigh
		}
		out = append(out, u.mk(
			"U22.mcp.legacy-manifest",
			"Legacy plugin/MCP manifest is publicly served",
			severity, findings.ConfidenceFirm,
			origin+p,
			fmt.Sprintf("GET %s returned 200 with structured content (%d bytes, Content-Type: %s). An unauthenticated attacker can enumerate the entire tool/endpoint surface without needing to invoke it.", p, len(body), ct),
			"CWE-200",
			"Move the manifest behind authentication or into a private /internal path. The manifest is the attacker's map; serving it anonymously means the first stage of an attack is free.",
		))
	}
	return out
}

// ── U23: MCP-Protocol-Version fuzz ─────────────────────────────────────

func (u *Unauth) checkVersionFuzz(ctx context.Context, rawURL string) []findings.Finding {
	// Reference: a well-known-invalid version string. A strict server rejects
	// this; a sloppy server accepts it and then fails later with an obscure
	// error (or worse, treats it as a default).
	fuzz := []string{
		"1999-01-01",
		"not-a-version",
		"' OR 1=1--",
		strings.Repeat("A", 1024),
	}
	accepted := 0
	for _, v := range fuzz {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL,
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+v+`","capabilities":{},"clientInfo":{"name":"seyon-fuzz","version":"1"}}}`))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", v)
		resp, err := u.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<17))
		_ = resp.Body.Close()
		// 200 with a non-error result = server accepted a nonsense version
		if resp.StatusCode == 200 {
			var env struct {
				Result *json.RawMessage `json:"result"`
				Error  *json.RawMessage `json:"error"`
			}
			if err := json.Unmarshal(body, &env); err == nil && env.Error == nil && env.Result != nil {
				accepted++
			}
		}
	}
	if accepted == 0 {
		return nil
	}
	return []findings.Finding{u.mk(
		"U23.mcp.version-fuzz",
		"Server accepts arbitrary MCP-Protocol-Version values",
		findings.SeverityMedium, findings.ConfidenceFirm,
		rawURL,
		fmt.Sprintf("%d of 4 fuzzed protocol-version strings (including SQL-injection and 1KB payloads) were accepted with a 200 success result. The server is not validating the version negotiation input.", accepted),
		"CWE-20",
		"Validate protocolVersion against an allowlist (the versions the server implements). Reject unknown values with a JSON-RPC error. Sloppy validation here is often an upstream library parsing bug waiting to surface.",
	)}
}

// ── U24: tool / method leak in error body ──────────────────────────────

var leakyKeysRe = regexp.MustCompile(`(?i)"(tools|methods|available_methods|capabilities|endpoints|routes)"\s*:`)
var mcpToolNameRe = regexp.MustCompile(`"name"\s*:\s*"([a-zA-Z_][a-zA-Z0-9_.-]{2,80})"`)

func (u *Unauth) checkToolLeakInError(ctx context.Context, rawURL string) []findings.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"nonexistent/method"}`))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<17))
	_ = resp.Body.Close()
	if resp.StatusCode < 400 || len(body) < 20 {
		return nil
	}
	hasLeakyKey := leakyKeysRe.Match(body)
	names := mcpToolNameRe.FindAllSubmatch(body, 10)
	if !hasLeakyKey && len(names) == 0 {
		return nil
	}
	var evidence []string
	if hasLeakyKey {
		evidence = append(evidence, "surface-enumeration keys")
	}
	if len(names) > 0 {
		seen := map[string]bool{}
		var sample []string
		for _, m := range names {
			n := string(m[1])
			if !seen[n] && len(sample) < 5 {
				sample = append(sample, n)
				seen[n] = true
			}
		}
		evidence = append(evidence, fmt.Sprintf("method/tool names in error body: %s", strings.Join(sample, ", ")))
	}
	return []findings.Finding{u.mk(
		"U24.mcp.leak-in-error",
		"Error response enumerates tool or method names to unauthenticated callers",
		findings.SeverityMedium, findings.ConfidenceFirm,
		rawURL,
		fmt.Sprintf("the %d error response contains %s. 'Helpful' error messages give an attacker the full attack surface without needing valid credentials.", resp.StatusCode, strings.Join(evidence, " · ")),
		"CWE-209",
		"Make the error path uniform: return a generic 'method not found' / 'unauthorized' with no server-side knowledge of what IS available. Log the detail server-side if you need to debug.",
	)}
}

// ── U25: OAuth authorization open-redirect probe ───────────────────────

func (u *Unauth) checkOAuthOpenRedirect(ctx context.Context, target *url.URL) []findings.Finding {
	// Re-fetch discovery (cheap). If no authorization_endpoint, skip.
	origin := target.Scheme + "://" + target.Host
	meta := u.fetchOAuthMetadata(ctx, origin)
	if meta == nil || meta.AuthorizationEndpoint == "" {
		return nil
	}

	// Craft a probe URL. We intentionally use a client_id of "seyon-probe"
	// that no server has registered — we care only about redirect_uri
	// validation, not whether the client exists. A properly-configured server
	// rejects with "invalid_client" or "invalid_redirect_uri" BEFORE
	// redirecting. A misconfigured server 302s to the attacker URL.
	authU, err := url.Parse(meta.AuthorizationEndpoint)
	if err != nil {
		return nil
	}
	q := authU.Query()
	q.Set("response_type", "code")
	q.Set("client_id", "seyon-probe-does-not-exist")
	q.Set("redirect_uri", "https://seyon-probe.example/catcher")
	q.Set("state", "seyon-probe")
	q.Set("scope", "openid")
	authU.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authU.String(), nil)
	if err != nil {
		return nil
	}
	// Don't follow redirects — the 302 itself is the evidence.
	resp, err := u.client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if strings.HasPrefix(loc, "https://seyon-probe.example/") ||
			strings.HasPrefix(loc, "http://seyon-probe.example/") {
			return []findings.Finding{u.mk(
				"U25.oauth.open-redirect",
				"OAuth authorization endpoint accepts attacker-controlled redirect_uri",
				findings.SeverityHigh, findings.ConfidenceFirm,
				meta.AuthorizationEndpoint,
				fmt.Sprintf("probe URL with client_id=seyon-probe-does-not-exist&redirect_uri=https://seyon-probe.example/catcher was followed with a %d Location: %s. An attacker who tricks a user into clicking a crafted auth link can harvest the authorization code at the attacker's catcher URL.", resp.StatusCode, loc),
				"CWE-601",
				"Validate redirect_uri against each client's pre-registered list BEFORE issuing any redirect. Reject with `invalid_request` when it doesn't match. This is OAuth 2.0 §3.1.2 (REQUIRED, not SHOULD).",
			)}
		}
	}
	return nil
}

func (u *Unauth) fetchOAuthMetadata(ctx context.Context, origin string) *oauthMetadata {
	for _, p := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+p, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		resp, err := u.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		var meta oauthMetadata
		if err := json.Unmarshal(body, &meta); err == nil && meta.Issuer != "" {
			return &meta
		}
	}
	return nil
}

// ── U26: JWKS deep inspection ──────────────────────────────────────────

type jwksSet struct {
	Keys []jwksKey `json:"keys"`
}

type jwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (u *Unauth) checkJWKS(ctx context.Context, target *url.URL) []findings.Finding {
	origin := target.Scheme + "://" + target.Host
	meta := u.fetchOAuthMetadata(ctx, origin)
	if meta == nil || meta.JWKSURI == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.JWKSURI, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	var set jwksSet
	if err := json.Unmarshal(body, &set); err != nil || len(set.Keys) == 0 {
		return nil
	}

	var out []findings.Finding
	kidSeen := map[string]int{}
	for _, k := range set.Keys {
		if k.Kid != "" {
			kidSeen[k.Kid]++
		}
		switch strings.ToUpper(k.Kty) {
		case "RSA":
			bits := estimateRSAKeySize(k.N)
			switch {
			case bits > 0 && bits < 2048:
				out = append(out, u.mk(
					"U26.jwks.rsa-weak",
					"JWKS contains an RSA key below 2048 bits",
					findings.SeverityCritical, findings.ConfidenceFirm,
					meta.JWKSURI,
					fmt.Sprintf("key kid=%q is RSA-%d; factorable with modern hardware and rejected by every current standard (NIST SP 800-57, PCI-DSS 4.0)", k.Kid, bits),
					"CWE-326",
					"Rotate the key to RSA-2048 (floor) or RSA-3072 (preferred) immediately. Revoke the weak key and reissue every token that was signed with it.",
				))
			case bits == 2048:
				// Common; not a finding, but note.
			case bits >= 4096:
				// Great. No finding.
			}
		case "EC":
			if k.Crv == "P-192" || k.Crv == "secp192r1" {
				out = append(out, u.mk(
					"U26.jwks.ec-weak-curve",
					"JWKS contains an EC key on a weak curve",
					findings.SeverityHigh, findings.ConfidenceFirm,
					meta.JWKSURI,
					fmt.Sprintf("key kid=%q uses curve %s; P-192 is deprecated and rejected by RFC 7518 for JWS signatures", k.Kid, k.Crv),
					"CWE-326",
					"Rotate to P-256 (ES256), P-384 (ES384), or Ed25519 (EdDSA). All three are RFC 7518 or RFC 8037 compliant.",
				))
			}
		case "OCT":
			// Symmetric key advertised in JWKS = HS256 situation. Not fatal
			// here (we already warn in U14) — but a kid without use="sig"
			// means it may be mistakenly used for encryption.
		}
	}

	// Duplicate kid → signature ambiguity; a token can be verified against
	// either key, which weakens the audit trail.
	for kid, count := range kidSeen {
		if count > 1 {
			out = append(out, u.mk(
				"U26.jwks.duplicate-kid",
				"JWKS contains duplicate kid values",
				findings.SeverityMedium, findings.ConfidenceFirm,
				meta.JWKSURI,
				fmt.Sprintf("kid=%q appears %d times. JWT verifiers that select by kid now have ambiguous input; an attacker can force the weaker key.", kid, count),
				"CWE-347",
				"Every kid in a JWKS must be unique. Remove the duplicate or rotate so only one key answers to a given kid.",
			))
		}
	}

	// Sequential-integer kids (0, 1, 2, ...) = low entropy, and indicate the
	// issuer doesn't rotate properly. Not a vuln on its own but a hygiene
	// smell.
	if looksLikeSequentialKids(set.Keys) {
		out = append(out, u.mk(
			"U26.jwks.sequential-kids",
			"JWKS kid values are sequential integers",
			findings.SeverityInfo, findings.ConfidenceTentative,
			meta.JWKSURI,
			fmt.Sprintf("kids look sequential (%v). Low-entropy kids suggest the issuer does not rotate keys and does not use random key identifiers.", kidList(set.Keys)),
			"CWE-331",
			"Use a random kid (UUID, 128-bit random string, or truncated SHA-256 of the public key). Sequential kids are a hygiene smell more than a vuln but correlate with poor key rotation.",
		))
	}

	return out
}

func estimateRSAKeySize(nB64 string) int {
	data, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		// Try standard padding as fallback.
		data, err = base64.URLEncoding.DecodeString(nB64)
		if err != nil {
			return 0
		}
	}
	n := new(big.Int).SetBytes(data)
	bits := n.BitLen()
	// Round to nearest 128.
	return (bits + 127) / 128 * 128
}

// Unused but imported for future extension hooks (ecdsa/rsa key reconstruction).
var _ = ecdsa.PublicKey{}
var _ = rsa.PublicKey{}

func looksLikeSequentialKids(keys []jwksKey) bool {
	if len(keys) < 2 {
		return false
	}
	var nums []int
	for _, k := range keys {
		n, err := strconv.Atoi(k.Kid)
		if err != nil {
			return false
		}
		nums = append(nums, n)
	}
	sort.Ints(nums)
	for i := 1; i < len(nums); i++ {
		if nums[i]-nums[i-1] != 1 {
			return false
		}
	}
	return true
}

func kidList(keys []jwksKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k.Kid != "" {
			out = append(out, k.Kid)
		}
	}
	return out
}

// ── U27: WAF / reverse-proxy header bypass ─────────────────────────────

// Classic bypass-the-edge-WAF headers. A server that honors any of these at
// the application layer trusts request-header input for routing decisions,
// which an attacker can abuse to reach supposedly-internal paths.
var wafBypassProbes = []struct {
	header string
	value  string
	why    string
}{
	{"X-Original-URL", "/admin", "IIS / Node URL rewrite — reaches /admin despite the edge WAF routing /mcp"},
	{"X-Rewrite-URL", "/admin", "Apache / Node URL rewrite with the same effect"},
	{"X-Forwarded-Host", "internal.local", "spoofs the virtual-host header; some backends dispatch on this"},
	{"X-Forwarded-For", "127.0.0.1", "spoofs client IP; some apps grant admin privileges to loopback callers"},
	{"CF-Connecting-IP", "127.0.0.1", "Cloudflare-specific — origin servers sometimes trust this unconditionally"},
	{"X-Real-IP", "127.0.0.1", "nginx proxy_set_header — same trust-the-header problem"},
}

func (u *Unauth) checkWAFBypass(ctx context.Context, rawURL string) []findings.Finding {
	// Baseline: fetch the endpoint without any bypass header and record the
	// status code. We flag ONLY headers whose presence changes the status
	// code (401 → 200/302), which filters out the dozens of servers that
	// return the same 404 no matter what.
	baseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	baseResp, err := u.client.Do(baseReq)
	if err != nil {
		return nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(baseResp.Body, 4096))
	_ = baseResp.Body.Close()
	baseStatus := baseResp.StatusCode

	var abuses []string
	for _, probe := range wafBypassProbes {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set(probe.header, probe.value)
		resp, err := u.client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode != baseStatus &&
			(resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302) {
			abuses = append(abuses, fmt.Sprintf("%s: %s → %d (baseline was %d) — %s",
				probe.header, probe.value, resp.StatusCode, baseStatus, probe.why))
		}
	}
	if len(abuses) == 0 {
		return nil
	}
	return []findings.Finding{u.mk(
		"U27.waf.bypass",
		"Server changes response based on untrusted request headers",
		findings.SeverityHigh, findings.ConfidenceFirm,
		rawURL,
		"the following headers altered the response in a way consistent with a WAF/edge-proxy bypass:\n  - "+strings.Join(abuses, "\n  - "),
		"CWE-290",
		"Do not trust client-supplied headers for routing or auth decisions at the application layer. If your reverse proxy sets X-Forwarded-For / CF-Connecting-IP, overwrite them at the edge and reject requests that set them from outside.",
	)}
}

// ── U28: auth-attempt rate limiting ────────────────────────────────────

func (u *Unauth) checkAuthRateLimit(ctx context.Context, rawURL string) []findings.Finding {
	// 15 rapid requests, each with a different bad bearer token. A
	// well-defended endpoint responds 401 three or four times, then 429.
	// A poorly-defended one keeps returning 401 indefinitely.
	accepted := 0
	rateLimited := false
	for i := 0; i < 15; i++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer invalid-token-%d-%d", i, time.Now().UnixNano()))
		resp, err := u.client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode == 429 {
			rateLimited = true
			break
		}
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			accepted++
		}
	}
	if rateLimited || accepted < 10 {
		return nil
	}
	return []findings.Finding{u.mk(
		"U28.auth.rate-limit-missing",
		"Server does not rate-limit failed-auth attempts",
		findings.SeverityHigh, findings.ConfidenceFirm,
		rawURL,
		fmt.Sprintf("sent %d bad bearer tokens in quick succession; every one returned 401/403 with no 429. An attacker can brute-force or credential-stuff this endpoint without any throttling.", accepted),
		"CWE-307",
		"Rate-limit failed auth attempts separately from successful requests. 3-5 failures per IP per minute, with exponential backoff, is the standard. Without this, token-leak detection is the only line of defense against bulk credential testing.",
	)}
}
