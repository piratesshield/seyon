package probe

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"seyon/internal/findings"
)

// RunJWTFuzz performs alg-confusion and kid-manipulation fuzzing against the
// MCP endpoint, but only when the caller supplied a bearer token that parses
// as a JWT. The checks send intentionally malformed variants of the real
// token and look for the ONE outcome that should never happen: the server
// returns 200 for a token that was not signed correctly.
//
// Rule IDs J1-J4. Safe: we send exactly as many requests as there are
// attack vectors (~4). No tool invocation.
func (u *Unauth) RunJWTFuzz(ctx context.Context, rawURL string) []findings.Finding {
	auth := u.headers.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return nil
	}
	token := strings.TrimSpace(auth[len("Bearer "):])
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		// Not a JWT — nothing to fuzz.
		return nil
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	var hdr map[string]interface{}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil
	}
	var pay map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &pay); err != nil {
		return nil
	}

	// Baseline: the real token must still return a 2xx. If not, the token is
	// expired/invalid and fuzzing is meaningless.
	if ok, _ := u.probeToken(ctx, rawURL, token); !ok {
		return nil
	}

	var out []findings.Finding

	// J1 — alg=none: strip the signature, set alg=none. A compliant server
	// must reject. A library that uses the token's own alg header to pick a
	// verifier accepts it.
	{
		alt := copyJWTMap(hdr)
		alt["alg"] = "none"
		altToken := makeJWT(alt, pay, "")
		if ok, status := u.probeToken(ctx, rawURL, altToken); ok {
			out = append(out, u.mk(
				"J1.jwt.alg-none-accepted",
				"Server accepts a JWT with alg=none",
				findings.SeverityCritical, findings.ConfidenceFirm,
				rawURL,
				fmt.Sprintf("re-sent the current token with its header rewritten to {\"alg\":\"none\"} and the signature stripped; server returned %d. Any attacker who can read one token can forge arbitrary tokens.", status),
				"CWE-347",
				"Pin the accepted algorithm on the server side; do not derive it from the token header. The JWT RFC 7519 attack class has been fixed in every mainstream library — if you see this, your verification code is bespoke.",
			))
		}
	}

	// J2 — kid traversal: set kid to a path-traversal string. A library that
	// loads the key file from disk based on the kid may read an unintended
	// file (e.g. /dev/null, which gives a known key).
	{
		alt := copyJWTMap(hdr)
		alt["kid"] = "../../../../dev/null"
		// Keep the original signature — if the server resolves kid to a
		// filesystem path and reads an unintended file as the HMAC secret,
		// the attacker learns a predictable key source.
		altToken := makeJWT(alt, pay, parts[2])
		if ok, status := u.probeToken(ctx, rawURL, altToken); ok {
			out = append(out, u.mk(
				"J2.jwt.kid-traversal",
				"Server accepts a JWT with path-traversal kid",
				findings.SeverityHigh, findings.ConfidenceTentative,
				rawURL,
				fmt.Sprintf("re-sent the token with kid set to '../../../../dev/null'; server returned %d. If the verifier resolves kid to a filesystem path, the attacker can direct it to a predictable key source.", status),
				"CWE-23",
				"Treat kid as an opaque key ID, not a filesystem path. Validate against a pre-registered key set only.",
			))
		}
	}

	// J3 — alg switch (RS256 → HS256): if the token was signed with RS256,
	// an attacker who knows the public key can sign an HS256 token using the
	// public key as the HMAC secret. The server, if it picks alg from the
	// header, will try to verify HS256 using whatever "key" the verifier
	// loads for this kid — often the public key itself.
	if origAlg, _ := hdr["alg"].(string); strings.HasPrefix(origAlg, "RS") || strings.HasPrefix(origAlg, "ES") {
		alt := copyJWTMap(hdr)
		alt["alg"] = "HS256"
		// Forge a token with an empty HS256 "signature". We don't need the
		// real public key — the probe is whether the server even attempts
		// HS verification when the original was RS256. A properly
		// configured server rejects on alg mismatch before signature check.
		altToken := makeJWT(alt, pay, "")
		if ok, status := u.probeToken(ctx, rawURL, altToken); ok {
			out = append(out, u.mk(
				"J3.jwt.alg-switch",
				"Server accepts a JWT with downgraded signing algorithm",
				findings.SeverityHigh, findings.ConfidenceFirm,
				rawURL,
				fmt.Sprintf("original token used %s; re-sent with alg rewritten to HS256 and empty signature; server returned %d. The verifier is picking algorithm from the token header — the class-of-attack is CVE-2016-5431.", origAlg, status),
				"CWE-345",
				"Pin the server's expected algorithm. Never allow the token's alg header to choose between RS and HS verification paths.",
			))
		}
	}

	// J4 — expiry stripped: remove 'exp' from payload, resend with original
	// signature (which is now invalid). A server that doesn't verify the
	// signature but reads claims naively will accept this token forever.
	// (This is a weird failure mode but we've seen it in homebrew backends.)
	if _, hasExp := pay["exp"]; hasExp {
		alt := copyJWTMap(pay)
		delete(alt, "exp")
		altToken := makeJWT(hdr, alt, parts[2]) // keep original (now-invalid) sig
		if ok, status := u.probeToken(ctx, rawURL, altToken); ok {
			out = append(out, u.mk(
				"J4.jwt.sig-unverified",
				"Server accepts a JWT with stale signature after claim modification",
				findings.SeverityCritical, findings.ConfidenceFirm,
				rawURL,
				fmt.Sprintf("re-sent the token with 'exp' claim removed; signature is now invalid; server still returned %d. The verifier is not validating the signature at all — any attacker who harvests a token has permanent access.", status),
				"CWE-347",
				"Validate the signature on every request. This is often a misconfigured JWT library (e.g. jsonwebtoken `verify()` vs `decode()`).",
			))
		}
	}

	return out
}

// probeToken sends a minimal MCP initialize with the given bearer token.
// Returns (acceptedByServer, statusCode). Accepted = 200.
func (u *Unauth) probeToken(ctx context.Context, rawURL, token string) (bool, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL,
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"seyon-jwt-fuzz","version":"1"}}}`))
	if err != nil {
		return false, 0
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := u.client.Do(req)
	if err != nil {
		return false, 0
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode == 200, resp.StatusCode
}

func copyJWTMap(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func makeJWT(header, payload map[string]interface{}, sig string) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + "." + sig
}

// Compile-time reminder that u.headers may hold non-bearer schemes;
// consumers of RunJWTFuzz must check Authorization: Bearer themselves.
var _ = bytes.NewReader
var _ = url.Parse
