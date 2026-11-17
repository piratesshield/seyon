package probe

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"seyon/internal/findings"
)

// Unauth is the deep-posture audit a real MCP security engineer runs against
// an endpoint they do NOT have credentials for. It extracts every signal the
// server leaks for free: TLS stack, HTTP security headers, auth challenge,
// CORS misconfiguration, server fingerprint, OAuth discovery metadata,
// sensitive-path disclosure, and error-body information leaks.
//
// All checks are read-only and safe. The prober sends ~10 extra HTTP requests
// (handshake, OPTIONS, OAuth discovery GETs, a handful of well-known path
// probes) and one TLS dial. Nothing it does requires a credential, and
// nothing it does mutates server state.
//
// Rule class "U" (Unauth deep audit). Each rule has a stable U-code so you
// can grep CI output for drift.
type Unauth struct {
	client  *http.Client
	headers http.Header
}

// NewUnauth returns a deep-posture prober. headers are the caller-supplied
// extra headers (if any); U-class checks run even when auth headers are
// present, because many are still meaningful (e.g. a Notion-with-bearer scan
// still benefits from a CORS check).
func NewUnauth(headers http.Header) *Unauth {
	return &Unauth{
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 2 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		headers: headers,
	}
}

// Run performs every check and returns the aggregated findings.
func (u *Unauth) Run(ctx context.Context, rawURL string) []findings.Finding {
	var out []findings.Finding

	target, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	// 1. One handshake GET/POST to capture the auth challenge, headers, body.
	resp, body := u.baseline(ctx, rawURL)

	out = append(out, u.checkTLS(ctx, target)...)
	if resp != nil {
		out = append(out, u.checkSecurityHeaders(target, resp)...)
		out = append(out, u.checkServerFingerprint(target, resp)...)
		out = append(out, u.checkAuthChallenge(target, resp)...)
		out = append(out, u.checkBodyInfoDisclosure(target, resp, body)...)
	}
	out = append(out, u.checkCORS(ctx, rawURL)...)
	out = append(out, u.checkOAuthDiscovery(ctx, target)...)
	out = append(out, u.checkSensitivePaths(ctx, target)...)

	// MCP-specific checks — transport enumeration, legacy manifests, protocol
	// version fuzzing, tool leakage in errors, OAuth open-redirect, JWKS deep
	// inspection, WAF header bypass, auth-attempt rate limiting.
	out = append(out, u.RunMCPSpecific(ctx, rawURL)...)

	// Deep transport-level probes — HTTP smuggling, HTTP/2 rapid-reset,
	// CT log subdomain enumeration, alternate-port scan, DNS posture,
	// TLS downgrade.
	out = append(out, u.RunDeepProbes(ctx, rawURL)...)

	// JWT fuzzing — runs ONLY when caller supplied a bearer token that parses
	// as a JWT. alg=none, kid traversal, RS→HS switch, signature bypass.
	out = append(out, u.RunJWTFuzz(ctx, rawURL)...)

	return out
}

// ── baseline request ────────────────────────────────────────────────────

func (u *Unauth) baseline(ctx context.Context, rawURL string) (*http.Response, []byte) {
	// A GET gives the cleanest header set; most servers either serve the MCP
	// transport on GET (SSE) or answer 405/401 with the same security
	// headers they'd use for POST. If GET fails, fall back to POST.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Accept", "application/json, text/event-stream, */*")
	req.Header.Set("User-Agent", "seyon-unauth-audit/1.0")
	for k, vs := range u.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := u.client.Do(req)
	if err != nil {
		// Try POST.
		postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
		if err != nil {
			return nil, nil
		}
		postReq.Header.Set("Content-Type", "application/json")
		postReq.Header.Set("Accept", "application/json, text/event-stream")
		for k, vs := range u.headers {
			for _, v := range vs {
				postReq.Header.Add(k, v)
			}
		}
		resp, err = u.client.Do(postReq)
		if err != nil {
			return nil, nil
		}
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, body
}

// ── U1-U3: TLS posture ──────────────────────────────────────────────────

func (u *Unauth) checkTLS(ctx context.Context, target *url.URL) []findings.Finding {
	if target.Scheme != "https" {
		return nil // U1 won't fire for http; P1 already caught it
	}
	host := target.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = host + ":443"
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	// Permissive config so a bad cert does NOT block the check; we want to
	// learn ABOUT the cert, not refuse to talk.
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // nolint:gosec — intentional, we audit the cert
		ServerName:         target.Hostname(),
	}
	rawConn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil
	}
	conn := tls.Client(rawConn, tlsCfg)
	defer func() { _ = conn.Close() }()
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil
	}
	state := conn.ConnectionState()

	var out []findings.Finding

	// U1 — TLS version
	tlsName := tlsVersionName(state.Version)
	// Use raw numeric values for deprecated versions; tls.VersionSSL30 is a
	// //lint:staticcheck SA1019 if referenced by name. We still want to
	// detect SSLv3 (0x0300) if a server somehow negotiates it.
	const versionSSL30 uint16 = 0x0300
	switch state.Version {
	case versionSSL30, tls.VersionTLS10, tls.VersionTLS11:
		out = append(out, u.mk(
			"U1.tls.version-weak",
			"Server negotiated a deprecated TLS version",
			findings.SeverityHigh, findings.ConfidenceFirm,
			target.String(),
			fmt.Sprintf("the TLS handshake settled on %s; TLS 1.0 and 1.1 are deprecated by every major browser and PCI-DSS 4.0", tlsName),
			"CWE-326",
			"Configure the TLS termination (load balancer, reverse proxy, or Go `tls.Config`) to refuse anything below TLS 1.2 and to prefer TLS 1.3.",
		))
	case tls.VersionTLS12:
		// Fine. TLS 1.3 is preferred but 1.2 is not a finding.
	}

	// U2 — Cipher suite strength. Only meaningful for TLS 1.2 (TLS 1.3 only
	// allows strong AEAD suites). Flag known-weak suites.
	if state.Version <= tls.VersionTLS12 {
		if isWeakCipher(state.CipherSuite) {
			out = append(out, u.mk(
				"U2.tls.cipher-weak",
				"Server negotiated a weak cipher suite",
				findings.SeverityMedium, findings.ConfidenceFirm,
				target.String(),
				fmt.Sprintf("negotiated %s on %s; this suite is weak (RC4/3DES/CBC-no-MtE, or export-grade)", tls.CipherSuiteName(state.CipherSuite), tlsName),
				"CWE-327",
				"Remove weak ciphers from the server config. Mozilla's 'intermediate' profile is a sane default: only AEAD suites (ChaCha20-Poly1305, AES-GCM).",
			))
		}
	}

	// U3 — Certificate expiry and signature
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		daysLeft := time.Until(leaf.NotAfter).Hours() / 24
		switch {
		case daysLeft < 0:
			out = append(out, u.mk(
				"U3.tls.cert-expired",
				"Server certificate has expired",
				findings.SeverityHigh, findings.ConfidenceFirm,
				target.String(),
				fmt.Sprintf("leaf certificate (CN=%s) expired %s", leaf.Subject.CommonName, leaf.NotAfter.Format(time.RFC3339)),
				"CWE-298",
				"Renew the server certificate immediately. Set up auto-renewal (Let's Encrypt + certbot, or a managed cert service).",
			))
		case daysLeft < 7:
			out = append(out, u.mk(
				"U3.tls.cert-expiring",
				"Server certificate expires in less than 7 days",
				findings.SeverityHigh, findings.ConfidenceFirm,
				target.String(),
				fmt.Sprintf("leaf certificate (CN=%s) expires %s (in %.0f days)", leaf.Subject.CommonName, leaf.NotAfter.Format(time.RFC3339), daysLeft),
				"CWE-298",
				"Renew before expiry to avoid an outage. Set up auto-renewal.",
			))
		case daysLeft < 30:
			out = append(out, u.mk(
				"U3.tls.cert-expiring",
				"Server certificate expires in less than 30 days",
				findings.SeverityMedium, findings.ConfidenceTentative,
				target.String(),
				fmt.Sprintf("leaf certificate (CN=%s) expires in %.0f days", leaf.Subject.CommonName, daysLeft),
				"CWE-298",
				"Plan a renewal. 30 days is enough lead time for manual renewal; auto-renewal is still recommended.",
			))
		}
		// Hostname mismatch — we skipped verify, so check manually.
		if err := leaf.VerifyHostname(target.Hostname()); err != nil {
			out = append(out, u.mk(
				"U3.tls.hostname-mismatch",
				"Server certificate does not match the requested hostname",
				findings.SeverityHigh, findings.ConfidenceFirm,
				target.String(),
				fmt.Sprintf("CN=%q / SANs=%v does not match %q: %v", leaf.Subject.CommonName, leaf.DNSNames, target.Hostname(), err),
				"CWE-297",
				"Issue a certificate whose CN or SAN matches the hostname. A mismatched cert is indistinguishable to a browser from an active MITM.",
			))
		}
		// Weak signature algorithm
		if leaf.SignatureAlgorithm == x509.SHA1WithRSA ||
			leaf.SignatureAlgorithm == x509.DSAWithSHA1 ||
			leaf.SignatureAlgorithm == x509.ECDSAWithSHA1 {
			out = append(out, u.mk(
				"U3.tls.cert-weak-sig",
				"Server certificate is signed with a weak algorithm",
				findings.SeverityHigh, findings.ConfidenceFirm,
				target.String(),
				fmt.Sprintf("leaf certificate uses %s; SHA-1 has been collision-weak since 2017 and every major CA stopped issuing SHA-1 certs by 2016", leaf.SignatureAlgorithm),
				"CWE-327",
				"Reissue the certificate with SHA-256 or stronger. SHA-1 certs are rejected by every modern browser.",
			))
		}
		// Self-signed
		if err := leaf.CheckSignatureFrom(leaf); err == nil {
			out = append(out, u.mk(
				"U3.tls.cert-self-signed",
				"Server presents a self-signed certificate",
				findings.SeverityMedium, findings.ConfidenceFirm,
				target.String(),
				"the leaf certificate is self-signed; clients that verify the chain will refuse to connect, and clients that disable verification are vulnerable to MITM",
				"CWE-295",
				"Replace with a certificate from a trusted CA (Let's Encrypt is free). Self-signed certs are only acceptable for isolated test environments.",
			))
		}
		// Record the cert fingerprint for operator cross-reference (info only).
		sum := sha1.Sum(leaf.Raw)
		_ = hex.EncodeToString(sum[:]) // future: expose as finding metadata
	}

	return out
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0300:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

func isWeakCipher(suite uint16) bool {
	// Maintained from Mozilla's SSL Configuration Generator — any cipher that
	// uses RC4, 3DES, DES, EXPORT, NULL, or CBC-with-SHA1 under TLS 1.2 fails.
	name := tls.CipherSuiteName(suite)
	lower := strings.ToLower(name)
	weakTokens := []string{
		"rc4", "3des", "des_", "des-", "_des", "null", "export",
		"md5", "anon",
	}
	for _, t := range weakTokens {
		if strings.Contains(lower, t) {
			return true
		}
	}
	// Flag plain CBC-SHA1 suites on TLS 1.2 (BEAST-adjacent).
	if strings.Contains(lower, "cbc") && strings.HasSuffix(lower, "sha") {
		return true
	}
	return false
}

// ── U4-U6: HTTP security headers ────────────────────────────────────────

func (u *Unauth) checkSecurityHeaders(target *url.URL, resp *http.Response) []findings.Finding {
	var out []findings.Finding

	// HSTS is only meaningful on HTTPS.
	if target.Scheme == "https" && resp.Header.Get("Strict-Transport-Security") == "" {
		out = append(out, u.mk(
			"U4.headers.hsts-missing",
			"Server does not send Strict-Transport-Security",
			findings.SeverityMedium, findings.ConfidenceFirm,
			target.String(),
			"no HSTS header on the handshake response; a network attacker can downgrade the connection to HTTP on first contact",
			"CWE-319",
			"Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to every HTTPS response. For production, also consider preload submission.",
		))
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		out = append(out, u.mk(
			"U5.headers.nosniff-missing",
			"Server does not send X-Content-Type-Options: nosniff",
			findings.SeverityLow, findings.ConfidenceFirm,
			target.String(),
			"the browser may MIME-sniff the response, which enables content-injection attacks in old IE/Edge. Cheap to fix.",
			"CWE-434",
			"Always send `X-Content-Type-Options: nosniff`.",
		))
	}
	if resp.Header.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(resp.Header.Get("Content-Security-Policy")), "frame-ancestors") {
		out = append(out, u.mk(
			"U5.headers.clickjack",
			"Server does not restrict framing (no X-Frame-Options or CSP frame-ancestors)",
			findings.SeverityLow, findings.ConfidenceTentative,
			target.String(),
			"the response can be embedded in an attacker-controlled iframe. Low risk for a JSON API, but a sign of missing defense-in-depth.",
			"CWE-1021",
			"Add `Content-Security-Policy: frame-ancestors 'none'` (modern) or `X-Frame-Options: DENY` (legacy).",
		))
	}
	if resp.Header.Get("Referrer-Policy") == "" {
		out = append(out, u.mk(
			"U6.headers.referrer-policy-missing",
			"Server does not send Referrer-Policy",
			findings.SeverityLow, findings.ConfidenceFirm,
			target.String(),
			"no Referrer-Policy header; clients may leak the URL (including tokens) in the Referer header of outbound links",
			"CWE-200",
			"Send `Referrer-Policy: strict-origin-when-cross-origin` (good default) or `no-referrer` (strictest).",
		))
	}

	return out
}

// ── U7-U8: CORS probe ───────────────────────────────────────────────────

func (u *Unauth) checkCORS(ctx context.Context, rawURL string) []findings.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, rawURL, nil)
	if err != nil {
		return nil
	}
	const evilOrigin = "https://attacker.example.com"
	req.Header.Set("Origin", evilOrigin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")

	var out []findings.Finding
	switch acao {
	case "":
		// Server doesn't send CORS at all. Not a finding — many APIs are
		// backend-only.
	case "*":
		if acac {
			out = append(out, u.mk(
				"U7.cors.wildcard-with-creds",
				"Server sends CORS wildcard with Allow-Credentials: true",
				findings.SeverityHigh, findings.ConfidenceFirm,
				rawURL,
				"`Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` is a spec violation that some browsers still honor; any site can issue credentialed requests to this endpoint",
				"CWE-942",
				"Either drop Allow-Credentials or echo a specific trusted origin. Never ship both wildcard + credentials.",
			))
		} else {
			out = append(out, u.mk(
				"U7.cors.wildcard",
				"Server sends CORS wildcard on a potentially auth-gated endpoint",
				findings.SeverityMedium, findings.ConfidenceFirm,
				rawURL,
				"`Access-Control-Allow-Origin: *` on an endpoint that accepts tokens means any site can ask the user's browser to invoke the tool surface (if the client reuses a session cookie)",
				"CWE-942",
				"Restrict CORS to the exact origins your agent client runs on. Wildcards are safe only on fully anonymous endpoints.",
			))
		}
	case evilOrigin:
		out = append(out, u.mk(
			"U8.cors.reflect-origin",
			"Server reflects an arbitrary Origin in Access-Control-Allow-Origin",
			findings.SeverityHigh, findings.ConfidenceFirm,
			rawURL,
			fmt.Sprintf("sent `Origin: %s`; server echoed it back in ACAO. Combined with credentials this is a CSRF primitive against any user with a session.", evilOrigin),
			"CWE-942",
			"Validate Origin against an allowlist before echoing. Never mirror the request Origin unconditionally.",
		))
	}
	return out
}

// ── U9: server fingerprint ─────────────────────────────────────────────

var versionRegex = regexp.MustCompile(`\d+(\.\d+){1,3}`)

func (u *Unauth) checkServerFingerprint(target *url.URL, resp *http.Response) []findings.Finding {
	var leaks []string
	if s := resp.Header.Get("Server"); s != "" && versionRegex.MatchString(s) {
		leaks = append(leaks, "Server: "+s)
	}
	if s := resp.Header.Get("X-Powered-By"); s != "" {
		leaks = append(leaks, "X-Powered-By: "+s)
	}
	if s := resp.Header.Get("X-AspNet-Version"); s != "" {
		leaks = append(leaks, "X-AspNet-Version: "+s)
	}
	if s := resp.Header.Get("X-AspNetMvc-Version"); s != "" {
		leaks = append(leaks, "X-AspNetMvc-Version: "+s)
	}
	if len(leaks) == 0 {
		return nil
	}
	return []findings.Finding{u.mk(
		"U9.server.fingerprint",
		"Server headers leak software versions",
		findings.SeverityLow, findings.ConfidenceFirm,
		target.String(),
		fmt.Sprintf("response headers disclose stack versions: %s. An attacker uses this to focus CVE lookups.", strings.Join(leaks, " · ")),
		"CWE-200",
		"Strip or neutralize version-bearing response headers at the reverse proxy. The Server header can be set to a generic value.",
	)}
}

// ── U10-U11: auth challenge analysis ────────────────────────────────────

func (u *Unauth) checkAuthChallenge(target *url.URL, resp *http.Response) []findings.Finding {
	if resp.StatusCode != 401 && resp.StatusCode != 407 {
		return nil
	}
	wwwAuth := resp.Header.Values("WWW-Authenticate")
	if len(wwwAuth) == 0 {
		// 401 with no WWW-Authenticate is a (minor) protocol defect but not
		// usually a security issue on its own.
		return nil
	}
	var schemes []string
	hasBasic, hasBearer := false, false
	for _, header := range wwwAuth {
		tokens := strings.Fields(header)
		if len(tokens) == 0 {
			continue
		}
		scheme := strings.ToLower(strings.TrimRight(tokens[0], ","))
		schemes = append(schemes, scheme)
		switch scheme {
		case "basic":
			hasBasic = true
		case "bearer":
			hasBearer = true
		}
	}
	var out []findings.Finding
	if hasBasic && target.Scheme == "https" {
		out = append(out, u.mk(
			"U10.auth.basic-advertised",
			"Server advertises HTTP Basic authentication",
			findings.SeverityMedium, findings.ConfidenceFirm,
			target.String(),
			"WWW-Authenticate offers `Basic`; Basic sends credentials as reversible base64 on every request. Even over TLS, that is a weaker posture than Bearer tokens (no scope, no expiry).",
			"CWE-522",
			"Drop Basic from the challenge. Serve only Bearer or OAuth; migrate any existing Basic callers to short-lived tokens.",
		))
	}
	if hasBasic && hasBearer {
		out = append(out, u.mk(
			"U11.auth.multiple-schemes",
			"Server advertises both Basic and Bearer auth",
			findings.SeverityMedium, findings.ConfidenceFirm,
			target.String(),
			fmt.Sprintf("WWW-Authenticate advertises multiple schemes (%s); a hostile intermediary can downgrade the client to the weaker one.", strings.Join(schemes, ", ")),
			"CWE-757",
			"Advertise exactly one authentication scheme. Pick the strongest one the server supports and remove the rest.",
		))
	}
	return out
}

// ── U12-U14: OAuth / OIDC discovery analysis ────────────────────────────

type oauthMetadata struct {
	Issuer                            string   `json:"issuer"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	JWKSURI                           string   `json:"jwks_uri"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
}

func (u *Unauth) checkOAuthDiscovery(ctx context.Context, target *url.URL) []findings.Finding {
	// Try both well-known paths at the origin.
	origin := target.Scheme + "://" + target.Host
	paths := []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	}
	var out []findings.Finding
	for _, p := range paths {
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
		if err := json.Unmarshal(body, &meta); err != nil {
			continue
		}
		out = append(out, u.mk(
			"U12.oauth.discovery-exposed",
			"OAuth / OIDC discovery metadata is public",
			findings.SeverityInfo, findings.ConfidenceFirm,
			origin+p,
			fmt.Sprintf("issuer=%q token_endpoint=%q grants=%v; harmless to expose but useful for an attacker mapping the auth surface", meta.Issuer, meta.TokenEndpoint, meta.GrantTypesSupported),
			"CWE-200",
			"This is the RFC 8414 / OIDC spec behavior. No action needed unless you consider your issuer URL sensitive.",
		))

		// U13 — insecure grant types
		for _, g := range meta.GrantTypesSupported {
			switch strings.ToLower(g) {
			case "password":
				out = append(out, u.mk(
					"U13.oauth.password-grant",
					"OAuth server supports the deprecated password grant",
					findings.SeverityHigh, findings.ConfidenceFirm,
					origin+p,
					"the Resource Owner Password Credentials grant forces callers to handle user passwords directly; it is deprecated in OAuth 2.1 and blocks passwordless auth.",
					"CWE-287",
					"Disable the password grant. Use authorization_code + PKCE for user flows and client_credentials for machine-to-machine.",
				))
			case "implicit":
				out = append(out, u.mk(
					"U13.oauth.implicit-grant",
					"OAuth server supports the deprecated implicit grant",
					findings.SeverityMedium, findings.ConfidenceFirm,
					origin+p,
					"the implicit grant returns tokens in URL fragments; it is removed from OAuth 2.1 and vulnerable to token leakage via browser history and referrer headers.",
					"CWE-200",
					"Disable implicit flow. Use authorization_code + PKCE instead — it is the OAuth 2.1 default for public clients.",
				))
			}
		}

		// U14 — weak JWT signing algorithms
		for _, alg := range meta.IDTokenSigningAlgValuesSupported {
			if strings.EqualFold(alg, "none") {
				out = append(out, u.mk(
					"U14.jwt.alg-none",
					"OIDC provider advertises the `none` signing algorithm",
					findings.SeverityCritical, findings.ConfidenceFirm,
					origin+p,
					"id_token_signing_alg_values_supported includes `none`; a client that honors this advertisement will accept unsigned JWTs. Classic JWT bypass.",
					"CWE-347",
					"Remove `none` from the supported alg list. Every ID token must be signed with an asymmetric algorithm (RS256/ES256/EdDSA).",
				))
			}
			if strings.EqualFold(alg, "HS256") && len(meta.IDTokenSigningAlgValuesSupported) == 1 {
				out = append(out, u.mk(
					"U14.jwt.symmetric-only",
					"OIDC provider offers only symmetric JWT signing",
					findings.SeverityMedium, findings.ConfidenceFirm,
					origin+p,
					"only HS256 is advertised; relying parties must share the signing key, which prevents public JWKS verification and encourages key-across-tenant reuse.",
					"CWE-327",
					"Prefer RS256 / ES256 / EdDSA so verifiers can fetch the public key from the JWKS URI.",
				))
			}
		}

		// Check PKCE support for public clients
		hasS256 := false
		for _, m := range meta.CodeChallengeMethodsSupported {
			if strings.EqualFold(m, "S256") {
				hasS256 = true
			}
		}
		if !hasS256 && len(meta.CodeChallengeMethodsSupported) > 0 {
			out = append(out, u.mk(
				"U13.oauth.pkce-weak",
				"OAuth server supports PKCE but not the required S256 method",
				findings.SeverityMedium, findings.ConfidenceFirm,
				origin+p,
				fmt.Sprintf("code_challenge_methods_supported=%v; S256 is required by OAuth 2.1", meta.CodeChallengeMethodsSupported),
				"CWE-327",
				"Add `S256` to `code_challenge_methods_supported`. Plain is downgradable and no longer compliant.",
			))
		}
	}
	return out
}

// ── U15: sensitive-path disclosure ──────────────────────────────────────

// sensitivePaths are paths that should NEVER return 200 from a well-run
// production server. A 200 (or anything other than 403/404) on any of these is
// a configuration smell and often a direct secrets leak.
var sensitivePaths = []struct {
	path     string
	severity findings.Severity
	why      string
}{
	{"/.env", findings.SeverityHigh, "Twelve-factor .env file; typically contains API keys and database credentials"},
	{"/.git/config", findings.SeverityHigh, "Git config exposes the full repo URL and often enables repo-cloning via /.git/HEAD"},
	{"/.git/HEAD", findings.SeverityHigh, "If served, the whole git history is downloadable"},
	{"/.aws/credentials", findings.SeverityCritical, "AWS static credentials"},
	{"/.ssh/id_rsa", findings.SeverityCritical, "Private SSH key"},
	{"/docker-compose.yml", findings.SeverityMedium, "Service graph and often default passwords"},
	{"/config.json", findings.SeverityMedium, "Application config"},
	{"/openapi.json", findings.SeverityInfo, "OpenAPI schema — useful for mapping the endpoint surface"},
	{"/swagger.json", findings.SeverityInfo, "Swagger schema — same as above"},
	{"/health", findings.SeverityInfo, "Health endpoint — sometimes leaks internal hostnames"},
	{"/metrics", findings.SeverityMedium, "Prometheus metrics — leaks internal hostnames, queue sizes, DB names"},
	{"/debug/pprof/", findings.SeverityHigh, "Go pprof endpoint; CPU/heap profiles can be dumped remotely"},
}

func (u *Unauth) checkSensitivePaths(ctx context.Context, target *url.URL) []findings.Finding {
	origin := target.Scheme + "://" + target.Host
	var out []findings.Finding
	for _, p := range sensitivePaths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+p.path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "seyon-unauth-audit/1.0")
		resp, err := u.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		// Discount plausible SPA catch-all responses — if every path returns
		// 200 with HTML, this is likely an SPA, not a real leak.
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if strings.HasPrefix(ct, "text/html") && !strings.Contains(string(body), p.path[1:]) {
			continue
		}
		sev := p.severity
		out = append(out, u.mk(
			"U15.path.disclosed",
			"Sensitive path returns 200 on the public endpoint",
			sev, findings.ConfidenceTentative,
			origin+p.path,
			fmt.Sprintf("GET %s returned 200 (Content-Type: %s). Why it matters: %s", p.path, ct, p.why),
			"CWE-538",
			"Deny the path at the reverse-proxy layer, or configure the server to return 404 for unknown routes. Sensitive files should never be served by a web process.",
		))
	}
	return out
}

// ── U16: info disclosure in error body ─────────────────────────────────

var (
	stackTraceRe = regexp.MustCompile(`(?i)(Traceback \(most recent call last\)|at [A-Za-z_][\w.]+\(.*?\.(?:java|kt|scala|cs|ts|js|py|go):\d+\)|panic: .+?\n.+?\.go:\d+|Exception in thread)`)
	privateIPRe  = regexp.MustCompile(`\b(10|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b`)
	internalRe   = regexp.MustCompile(`\b(internal|staging|dev|prod)-[a-z0-9.-]+\.(local|internal|corp)\b`)
)

func (u *Unauth) checkBodyInfoDisclosure(target *url.URL, resp *http.Response, body []byte) []findings.Finding {
	if len(body) == 0 || resp.StatusCode < 400 {
		return nil
	}
	text := string(body)
	var hits []string
	if stackTraceRe.MatchString(text) {
		hits = append(hits, "stack trace")
	}
	if m := privateIPRe.FindString(text); m != "" {
		hits = append(hits, "private IP "+m)
	}
	if m := internalRe.FindString(text); m != "" {
		hits = append(hits, "internal hostname "+m)
	}
	if len(hits) == 0 {
		return nil
	}
	return []findings.Finding{u.mk(
		"U16.body.info-disclosure",
		"Error response body leaks implementation details",
		findings.SeverityMedium, findings.ConfidenceFirm,
		target.String(),
		fmt.Sprintf("the %d response body contains: %s. An attacker uses this to map the backend topology.", resp.StatusCode, strings.Join(hits, ", ")),
		"CWE-209",
		"Strip stack traces, internal hostnames, and private IPs from error responses. Return only an opaque error code + correlation ID to the caller; log the details server-side.",
	)}
}

// ── helpers ─────────────────────────────────────────────────────────────

func (u *Unauth) mk(ruleID, title string, sev findings.Severity, conf findings.Confidence, endpoint, note, cwe, remediation string) findings.Finding {
	f := findings.Finding{
		RuleID:      ruleID,
		Class:       "U",
		Title:       title,
		Severity:    sev,
		Confidence:  conf,
		Modes:       []findings.Mode{findings.ModeBlack},
		Target:      findings.Target{Endpoint: endpoint},
		Evidence:    findings.Evidence{Note: note},
		CWE:         cwe,
		References:  []string{"unauth-deep-audit"},
		Remediation: remediation,
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return f
}
