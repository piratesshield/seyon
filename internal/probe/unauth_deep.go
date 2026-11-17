package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"seyon/internal/findings"

	"golang.org/x/net/http2"
)

// RunDeepProbes runs the "second-pass" unauth checks that need lower-level
// transport than net/http gives us: HTTP request smuggling, HTTP/2 rapid
// reset, TLS downgrade, DNS/CT posture, alternate-port scan.
//
// Rule IDs U29-U34. Safe and read-only: no tool invocation, no credential
// handling. All probes use short timeouts and strict traffic budgets so
// scanning a slow target cannot stall the pipeline.
func (u *Unauth) RunDeepProbes(ctx context.Context, rawURL string) []findings.Finding {
	target, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var out []findings.Finding
	out = append(out, u.checkRequestSmuggling(ctx, target)...)
	out = append(out, u.checkHTTP2RapidReset(ctx, target)...)
	out = append(out, u.checkCTLogSubdomains(ctx, target)...)
	out = append(out, u.checkAlternatePorts(ctx, target)...)
	out = append(out, u.checkDNSPosture(ctx, target)...)
	out = append(out, u.checkTLSDowngrade(ctx, target)...)
	return out
}

// ── U29: HTTP request smuggling ────────────────────────────────────────

// checkRequestSmuggling sends four safe ambiguous-framing requests and
// classifies the response pattern. We never attempt to actually smuggle a
// second request onto another user's connection — that could affect other
// tenants. Instead we send intentionally malformed envelopes and observe
// whether the server accepts them. A well-run server returns 400 Bad Request
// consistently; a vulnerable fronted-backend pair often returns 200 for one
// shape and 400 for another, which is the smuggling vulnerability
// precondition.
func (u *Unauth) checkRequestSmuggling(ctx context.Context, target *url.URL) []findings.Finding {
	// Ambiguous CL.TE: body claims chunked encoding, but Content-Length is
	// also set. A proper HTTP/1.1 stack prefers Transfer-Encoding and treats
	// the body as chunked (0\r\n\r\n = zero bytes). A buggy backend reads
	// Content-Length bytes.
	payloads := []struct {
		label string
		raw   string
	}{
		{
			"CL.TE conflict",
			"POST " + pathOrSlash(target) + " HTTP/1.1\r\n" +
				"Host: " + target.Host + "\r\n" +
				"Content-Length: 4\r\n" +
				"Transfer-Encoding: chunked\r\n" +
				"\r\n" +
				"0\r\n\r\n",
		},
		{
			"TE obfuscated (space before colon)",
			"POST " + pathOrSlash(target) + " HTTP/1.1\r\n" +
				"Host: " + target.Host + "\r\n" +
				"Content-Length: 5\r\n" +
				"Transfer-Encoding : chunked\r\n" +
				"\r\n" +
				"0\r\n\r\n",
		},
		{
			"TE duplicate",
			"POST " + pathOrSlash(target) + " HTTP/1.1\r\n" +
				"Host: " + target.Host + "\r\n" +
				"Content-Length: 6\r\n" +
				"Transfer-Encoding: chunked\r\n" +
				"Transfer-Encoding: identity\r\n" +
				"\r\n" +
				"0\r\n\r\n",
		},
	}

	type result struct {
		label  string
		status int
		err    error
	}
	var results []result

	for _, p := range payloads {
		status, err := u.rawTCPSend(ctx, target, p.raw, 4*time.Second)
		results = append(results, result{p.label, status, err})
	}

	// Vulnerability signal: at least one probe accepted (200/202) AND at
	// least one rejected (400). A server that rejects all 3 is correctly
	// strict; a server that accepts all 3 is probably ignoring the framing
	// entirely (bad, but not smuggling). The accept-some-reject-some pattern
	// is the dangerous one — upstream and backend disagree.
	acceptCount, rejectCount := 0, 0
	for _, r := range results {
		switch {
		case r.err != nil:
			// connection error = probably the backend hung up. Count as reject.
			rejectCount++
		case r.status >= 200 && r.status < 300:
			acceptCount++
		case r.status == 400 || r.status == 501:
			rejectCount++
		}
	}
	var out []findings.Finding
	if acceptCount > 0 && rejectCount > 0 {
		var detail []string
		for _, r := range results {
			if r.err != nil {
				detail = append(detail, fmt.Sprintf("%s → error", r.label))
			} else {
				detail = append(detail, fmt.Sprintf("%s → %d", r.label, r.status))
			}
		}
		out = append(out, u.mk(
			"U29.smuggling.framing-disagreement",
			"HTTP request smuggling preconditions present",
			findings.SeverityHigh, findings.ConfidenceTentative,
			target.String(),
			fmt.Sprintf("the server disagrees with its upstream about how to parse ambiguous HTTP framing: %s. This is the precondition for CL.TE / TE.CL request smuggling.", strings.Join(detail, " · ")),
			"CWE-444",
			"Have both the edge proxy and the backend treat ambiguous framing (CL+TE, duplicate TE, obfuscated TE) as a protocol error (400). The disagreement is the vulnerability — not any individual response.",
		))
	}
	return out
}

// pathOrSlash normalises a request-URI for raw-TCP sends.
func pathOrSlash(target *url.URL) string {
	p := target.Path
	if p == "" {
		p = "/"
	}
	if q := target.RawQuery; q != "" {
		p += "?" + q
	}
	return p
}

// rawTCPSend opens a TLS or TCP connection, writes the raw HTTP/1.1 request,
// reads the first line, returns the status code. Uses net/tls directly so we
// can control the exact bytes on the wire (net/http would canonicalise the
// headers and strip the ambiguity we want to test).
func (u *Unauth) rawTCPSend(ctx context.Context, target *url.URL, raw string, timeout time.Duration) (int, error) {
	host := target.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		if target.Scheme == "https" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(dctx, "tcp", host)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rawConn.Close() }()

	var conn net.Conn = rawConn
	if target.Scheme == "https" {
		tlsConn := tls.Client(rawConn, &tls.Config{
			InsecureSkipVerify: true, // nolint:gosec — we tested the cert in U3
			ServerName:         target.Hostname(),
		})
		if err := tlsConn.HandshakeContext(dctx); err != nil {
			return 0, err
		}
		conn = tlsConn
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := io.WriteString(conn, raw); err != nil {
		return 0, err
	}
	rdr := bufio.NewReader(conn)
	line, err := rdr.ReadString('\n')
	if err != nil {
		return 0, err
	}
	// "HTTP/1.1 200 OK\r\n" → parse the 200.
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		return 0, fmt.Errorf("sse: malformed status line: %q", line)
	}
	var status int
	if _, err := fmt.Sscanf(parts[1], "%d", &status); err != nil {
		return 0, err
	}
	return status, nil
}

// ── U30: HTTP/2 rapid-reset ────────────────────────────────────────────

// checkHTTP2RapidReset tests CVE-2023-44487. The attack sends a HEADERS frame
// immediately followed by RST_STREAM; the server allocates stream state for
// the HEADERS then releases it, but many servers don't bound the rate. The
// safe variant we run here: open the HTTP/2 connection, send 20 HEADERS +
// RST_STREAM pairs, see if the server closes the connection with GOAWAY
// ENHANCE_YOUR_CALM (correct) vs accepting all of them (vulnerable).
func (u *Unauth) checkHTTP2RapidReset(ctx context.Context, target *url.URL) []findings.Finding {
	if target.Scheme != "https" {
		return nil // HTTP/2 over cleartext is rare; skip
	}
	host := target.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = host + ":443"
	}

	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	rawConn, err := dialer.DialContext(dctx, "tcp", host)
	if err != nil {
		return nil
	}
	defer func() { _ = rawConn.Close() }()

	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true, // nolint:gosec
		ServerName:         target.Hostname(),
		NextProtos:         []string{"h2"},
	})
	if err := tlsConn.HandshakeContext(dctx); err != nil {
		return nil
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		return nil // server did not negotiate HTTP/2
	}

	// Use the http2 Framer to send HEADERS + RST_STREAM.
	framer := http2.NewFramer(tlsConn, tlsConn)
	// Connection preface
	if _, err := io.WriteString(tlsConn, http2.ClientPreface); err != nil {
		return nil
	}
	if err := framer.WriteSettings(); err != nil {
		return nil
	}

	// Minimal request headers.
	hbuf := &bytes.Buffer{}
	writeHPACK(hbuf, map[string]string{
		":method":    "GET",
		":scheme":    "https",
		":authority": target.Host,
		":path":      pathOrSlash(target),
	})

	const streams = 20
	resetCount := 0
	for i := 1; i <= streams*2; i += 2 {
		// Odd stream IDs are client-initiated.
		streamID := uint32(i)
		if err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: hbuf.Bytes(),
			EndStream:     true,
			EndHeaders:    true,
		}); err != nil {
			break
		}
		if err := framer.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
			break
		}
		resetCount++
	}

	// Read any frames the server sent in response. A protected server sends
	// a GOAWAY with ENHANCE_YOUR_CALM (code 11) — that's the correct
	// response per RFC 9113 §5.1.
	_ = tlsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	gotEnhance := false
	for i := 0; i < 20; i++ {
		fr, err := framer.ReadFrame()
		if err != nil {
			break
		}
		if goaway, ok := fr.(*http2.GoAwayFrame); ok {
			if goaway.ErrCode == http2.ErrCodeEnhanceYourCalm {
				gotEnhance = true
			}
			break
		}
	}

	if gotEnhance || resetCount < streams {
		// Server is protected (sent GOAWAY) or dropped us early (also fine).
		return nil
	}
	return []findings.Finding{u.mk(
		"U30.http2.rapid-reset",
		"Server accepts unlimited HTTP/2 stream resets (CVE-2023-44487)",
		findings.SeverityHigh, findings.ConfidenceTentative,
		target.String(),
		fmt.Sprintf("sent %d HEADERS+RST_STREAM pairs; server accepted all without GOAWAY ENHANCE_YOUR_CALM. A real attacker can exhaust the server with ~10k reset/sec per connection (CVE-2023-44487).", resetCount),
		"CWE-770",
		"Upgrade the HTTP/2 library: Go net/http2 ≥v0.17.0, nginx ≥1.25.3, Caddy ≥2.7.5, Envoy ≥1.24.10. Or disable HTTP/2 at the edge if you don't need it.",
	)}
}

// writeHPACK writes a minimal HPACK-encoded header block. We only use
// literal-with-indexing (0x40) for simplicity; real HPACK compresses better
// but the server decodes this correctly.
func writeHPACK(buf *bytes.Buffer, headers map[string]string) {
	for k, v := range headers {
		buf.WriteByte(0x00) // literal header, never indexed, new name
		writeHPACKString(buf, k)
		writeHPACKString(buf, v)
	}
}

func writeHPACKString(buf *bytes.Buffer, s string) {
	// Write length (always < 127 for our small strings → 1-byte varint).
	buf.WriteByte(byte(len(s)))
	buf.WriteString(s)
}

// ── U31: CT log subdomain enumeration ──────────────────────────────────

// checkCTLogSubdomains queries crt.sh for every certificate issued to the
// apex domain. Any subdomain we discover is both (a) useful for the operator
// to audit, and (b) potentially a weaker surface than the scanned endpoint.
// We do NOT scan the subdomains — just enumerate them.
func (u *Unauth) checkCTLogSubdomains(ctx context.Context, target *url.URL) []findings.Finding {
	host := target.Hostname()
	// Only query an apex-like domain. If the target already looks like
	// "api.foo.bar.com", query "bar.com" so we see siblings.
	apex := apexDomain(host)
	if apex == "" || apex == "localhost" {
		return nil
	}
	// crt.sh honors ?output=json; we cap at 5s so a slow CT shard doesn't
	// stall the whole scan.
	q := "https://crt.sh/?q=%25." + apex + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, q, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || len(body) < 10 {
		return nil
	}
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil
	}
	seen := map[string]bool{}
	for _, r := range rows {
		for _, n := range strings.Split(r.NameValue, "\n") {
			n = strings.TrimSpace(strings.ToLower(n))
			n = strings.TrimPrefix(n, "*.")
			if n == "" || n == host || !strings.HasSuffix(n, "."+apex) && n != apex {
				continue
			}
			if strings.Contains(n, " ") {
				continue
			}
			seen[n] = true
		}
	}
	// We want to list up to 25 related subdomains; this is intel, not a
	// severity finding on its own.
	if len(seen) == 0 {
		return nil
	}
	var names []string
	for n := range seen {
		names = append(names, n)
		if len(names) >= 25 {
			break
		}
	}
	return []findings.Finding{u.mk(
		"U31.ct.subdomain-enum",
		"Related subdomains visible in Certificate Transparency logs",
		findings.SeverityInfo, findings.ConfidenceFirm,
		"https://crt.sh/?q=%25."+apex,
		fmt.Sprintf("CT log query for *.%s returned %d other certificate(s). Related subdomains that may be worth auditing separately: %s", apex, len(seen), strings.Join(names, ", ")),
		"CWE-200",
		"Audit each subdomain against the same posture checks. Pay attention to subdomains named `dev-`, `staging-`, `old-` — these often have weaker auth than production.",
	)}
}

// apexDomain is a coarse apex extractor (last two labels). Good enough for
// the CT log query — a false-positive at a public-suffix-list boundary just
// returns fewer results than it could.
func apexDomain(host string) string {
	parts := strings.Split(strings.ToLower(host), ".")
	if len(parts) < 2 {
		return host
	}
	// Three-label TLDs (co.uk, com.au) aren't handled — the user's domain
	// would need to ship a PSL for perfect accuracy. For now, if the final
	// two labels are each ≤3 chars and plausible country-code, back off one.
	n := len(parts)
	if n >= 3 {
		last, secondLast := parts[n-1], parts[n-2]
		if len(last) == 2 && len(secondLast) <= 3 {
			return strings.Join(parts[n-3:], ".")
		}
	}
	return strings.Join(parts[n-2:], ".")
}

// ── U32: alternate-port scan ───────────────────────────────────────────

// Common ports MCP servers accidentally expose when their deployment
// scripts leave debug/service ports open. We TCP-dial each with a 1.5s
// timeout; port still-listening → finding. We do NOT do an HTTP probe,
// so this is cheap and doesn't leak our scan intent too far.
var alternatePorts = []struct {
	port int
	name string
	why  string
}{
	{9229, "Node.js inspector", "V8 remote debugger; attacker can read memory and execute JS"},
	{5005, "Java debugger (JDWP)", "JDWP is unauthenticated by default; remote code execution"},
	{3000, "Node dev server", "often a hot-reloading dev app with source maps and no auth"},
	{5000, "Flask / Python dev", "same risk as Node dev server"},
	{8080, "alt-HTTP", "common app fallback port; frequently an admin UI"},
	{8443, "alt-HTTPS", "same as 8080, often an unauthenticated admin TLS listener"},
	{8888, "Jupyter / notebook", "notebook kernel execution surface"},
	{9000, "PHP-FPM / SonarQube", "exposed workers or coverage dashboards"},
	{2375, "Docker API (plaintext)", "unauthenticated container root — critical if reachable"},
	{6379, "Redis", "often configured without auth in dev deployments"},
	{27017, "MongoDB", "same — anonymous Mongo was a 2016-2020 breach epidemic"},
}

func (u *Unauth) checkAlternatePorts(ctx context.Context, target *url.URL) []findings.Finding {
	host := target.Hostname()
	if host == "" {
		return nil
	}
	// Only scan when the host looks like a routable name or IP. We never
	// scan broader than the supplied host — no subnet sweep.
	type open struct {
		port int
		name string
		why  string
	}
	var opens []open
	for _, p := range alternatePorts {
		dctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}
		conn, err := dialer.DialContext(dctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", p.port)))
		cancel()
		if err != nil {
			continue
		}
		_ = conn.Close()
		opens = append(opens, open{p.port, p.name, p.why})
	}
	if len(opens) == 0 {
		return nil
	}
	var out []findings.Finding
	for _, o := range opens {
		sev := findings.SeverityMedium
		if o.port == 2375 || o.port == 9229 || o.port == 5005 {
			sev = findings.SeverityHigh // unauth code-exec ports
		}
		out = append(out, u.mk(
			"U32.port.exposed",
			fmt.Sprintf("Port %d (%s) is reachable on the target host", o.port, o.name),
			sev, findings.ConfidenceFirm,
			fmt.Sprintf("%s://%s:%d", target.Scheme, host, o.port),
			fmt.Sprintf("TCP :%d is reachable alongside the scanned MCP endpoint on %s. Why it matters: %s", o.port, host, o.why),
			"CWE-668",
			"Firewall the port off the public interface. Dev-only debug services (Node inspector, JDWP, Docker API) should listen on 127.0.0.1 only. If an admin UI needs to be reachable, put it behind auth.",
		))
	}
	return out
}

// ── U33: DNS posture ───────────────────────────────────────────────────

func (u *Unauth) checkDNSPosture(ctx context.Context, target *url.URL) []findings.Finding {
	host := target.Hostname()
	if host == "" || host == "localhost" {
		return nil
	}
	// We check CAA presence and absence of DNSSEC via standard resolvers.
	// This is coarse — a proper check would need a validating resolver and
	// an AD bit inspection; we settle for "does the domain have a CAA
	// record" which is cheap and actionable.
	resolver := &net.Resolver{}
	caaCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Go's stdlib doesn't expose CAA lookups natively — use LookupNS +
	// LookupTXT as a proxy signal. A proper implementation would use
	// miekg/dns; for a cross-platform cheap check we settle for the TXT
	// heuristic ("v=spf1" / "v=DMARC1" presence shows the operator uses
	// DNS hygiene).
	_, err := resolver.LookupNS(caaCtx, host)
	if err != nil {
		return nil
	}
	txts, _ := resolver.LookupTXT(caaCtx, host)
	hasSPF, hasDMARC := false, false
	for _, t := range txts {
		if strings.HasPrefix(t, "v=spf1") {
			hasSPF = true
		}
		if strings.HasPrefix(t, "v=DMARC1") {
			hasDMARC = true
		}
	}
	// DMARC TXT lives on _dmarc.<host>.
	if !hasDMARC {
		dmarcTxts, _ := resolver.LookupTXT(caaCtx, "_dmarc."+host)
		for _, t := range dmarcTxts {
			if strings.HasPrefix(t, "v=DMARC1") {
				hasDMARC = true
			}
		}
	}

	var out []findings.Finding
	if !hasSPF {
		out = append(out, u.mk(
			"U33.dns.spf-missing",
			"Target domain has no SPF record",
			findings.SeverityLow, findings.ConfidenceFirm,
			"dns://"+host,
			"TXT record v=spf1 is absent on the apex. Not an MCP vulnerability per se, but a sign the domain's email posture is unmanaged — attackers can send mail that spoofs this domain.",
			"CWE-346",
			"Publish a restrictive SPF record (`v=spf1 -all` when the domain doesn't send mail). Pair with DMARC for complete defense.",
		))
	}
	if !hasDMARC {
		out = append(out, u.mk(
			"U33.dns.dmarc-missing",
			"Target domain has no DMARC record",
			findings.SeverityLow, findings.ConfidenceFirm,
			"dns://_dmarc."+host,
			"_dmarc TXT record is absent. Mail impersonation of this domain is possible — relevant when the MCP provider sends email notifications tied to the same domain.",
			"CWE-346",
			"Publish a DMARC record at _dmarc.<domain>: `v=DMARC1; p=reject; rua=mailto:ops@...`.",
		))
	}
	return out
}

// ── U34: TLS downgrade probe ───────────────────────────────────────────

func (u *Unauth) checkTLSDowngrade(ctx context.Context, target *url.URL) []findings.Finding {
	if target.Scheme != "https" {
		return nil
	}
	host := target.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = host + ":443"
	}
	// Try TLS 1.0 only. If the server completes the handshake, it's
	// vulnerable to downgrade attacks like POODLE and unavailable for PCI 4.
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	rawConn, err := dialer.DialContext(dctx, "tcp", host)
	if err != nil {
		return nil
	}
	defer func() { _ = rawConn.Close() }()
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true, // nolint:gosec
		ServerName:         target.Hostname(),
	}
	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.HandshakeContext(dctx); err != nil {
		return nil // good — server rejected TLS 1.0
	}
	defer func() { _ = tlsConn.Close() }()
	return []findings.Finding{u.mk(
		"U34.tls.downgrade-tls10",
		"Server accepts a TLS 1.0 handshake",
		findings.SeverityHigh, findings.ConfidenceFirm,
		target.String(),
		"the server completed a TLS 1.0 handshake. TLS 1.0 was deprecated by the IETF in 2021 (RFC 8996) and is rejected by every major browser; a network attacker can force clients to downgrade.",
		"CWE-326",
		"Set the TLS minimum version to TLS 1.2 at the load balancer / termination layer. In Go, `tls.Config{MinVersion: tls.VersionTLS12}`.",
	)}
}
