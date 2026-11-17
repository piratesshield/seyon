package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"seyon/internal/findings"
	"seyon/internal/mcp"
)

// reconFromError turns a failed handshake into black-box observations (class A,
// transport/protocol). Black-box testing frequently runs without credentials,
// so a refused or absent endpoint is itself signal worth reporting — not a
// dead end. These are informational findings: they describe the endpoint's
// posture, never claim a vulnerability from a mere refusal.
func reconFromError(err error, endpoint string) []findings.Finding {
	mk := func(ruleID, title string, sev findings.Severity, note, body, rem string) findings.Finding {
		ev := findings.Evidence{Note: note}
		if body != "" {
			ev.Response = body
		}
		f := findings.Finding{
			RuleID:      ruleID,
			Class:       "A",
			Title:       title,
			Severity:    sev,
			Confidence:  findings.ConfidenceFirm, // directly observed from the live response
			Modes:       []findings.Mode{findings.ModeBlack},
			Target:      findings.Target{Endpoint: endpoint},
			Evidence:    ev,
			References:  []string{"black-box-recon"},
			Remediation: rem,
			StageStatus: findings.StageCompleted,
		}
		f.ID = f.Fingerprint()
		return f
	}

	var he *mcp.HTTPStatusError
	if errors.As(err, &he) {
		switch {
		case he.Code == 401 || he.Code == 403 || he.Code == 407:
			return []findings.Finding{mk(
				"A.endpoint.auth-required",
				"MCP endpoint requires authentication",
				findings.SeverityInfo,
				fmt.Sprintf("the server refused the unauthenticated handshake with HTTP %d; the MCP surface is auth-gated", he.Code),
				he.Body,
				"No action from a posture standpoint — the endpoint enforces authentication. To scan the authenticated surface, re-run with a valid credential for the endpoint.",
			)}
		case he.Code == 404 || he.Code == 410:
			return []findings.Finding{mk(
				"A.endpoint.not-found",
				"No MCP endpoint at this path",
				findings.SeverityInfo,
				fmt.Sprintf("the target returned HTTP %d to the handshake; this path is not an MCP endpoint", he.Code),
				he.Body,
				"Point the scan at the server's actual MCP path (commonly /mcp or /sse).",
			)}
		case he.Code == 405 || he.Code == 406:
			return []findings.Finding{mk(
				"A.endpoint.transport-mismatch",
				"MCP endpoint rejected the transport",
				findings.SeverityInfo,
				fmt.Sprintf("the server answered the handshake with HTTP %d — the URL likely speaks a different MCP transport than attempted", he.Code),
				he.Body,
				"If scanning the Streamable HTTP path, try the legacy SSE URL (commonly /sse) and vice versa. The scanner now tries both automatically on well-formed URLs.",
			)}
		case he.Code == 429:
			return []findings.Finding{mk(
				"A.endpoint.rate-limited",
				"MCP endpoint rate-limited the handshake",
				findings.SeverityInfo,
				"the server answered the handshake with HTTP 429; it applies rate limiting",
				he.Body,
				"Retry later or reduce request rate; rate limiting is a positive posture.",
			)}
		case he.Code >= 500:
			return []findings.Finding{mk(
				"A.endpoint.server-error",
				"MCP endpoint returned a server error during handshake",
				findings.SeverityLow,
				fmt.Sprintf("the server answered the handshake with HTTP %d; it may be misconfigured or failing", he.Code),
				he.Body,
				"Investigate the server-side error; a 5xx on a basic handshake can indicate an unhandled code path.",
			)}
		default:
			return []findings.Finding{mk(
				"A.handshake.rejected",
				"MCP handshake rejected",
				findings.SeverityInfo,
				fmt.Sprintf("the server rejected the handshake with HTTP %d", he.Code),
				he.Body,
				"Confirm the endpoint speaks the MCP Streamable HTTP transport and the protocol version is accepted.",
			)}
		}
	}

	// Protocol-version mismatch: the server spoke MCP but refused every version
	// this client offered. Record exactly which versions were tried so the
	// operator can tell whether the client or the server is stale.
	msg := err.Error()
	if strings.Contains(msg, "no mutually supported protocol version") {
		return []findings.Finding{mk(
			"A.protocol.version-mismatch",
			"MCP protocol version mismatch",
			findings.SeverityInfo,
			"the server answered the handshake but rejected every protocol version this client speaks",
			truncate(msg, 400),
			"The server likely runs a newer or older MCP spec revision. Upgrade Seyon (newer servers) or check whether the server declared an incompatible range.",
		)}
	}

	// Context deadline: slow server or network. Distinguish from unreachable.
	if errors.Is(err, context.DeadlineExceeded) {
		return []findings.Finding{mk(
			"A.transport.timeout",
			"MCP endpoint did not respond before timeout",
			findings.SeverityInfo,
			"the handshake exceeded the dial timeout; the endpoint is reachable but did not complete negotiation in time",
			"",
			"Retry with a longer timeout, or confirm the server is healthy and the network path does not add latency.",
		)}
	}

	// DNS / connection-refused: the target cannot be reached at all.
	if strings.Contains(msg, "no such host") || strings.Contains(msg, "connection refused") {
		return []findings.Finding{mk(
			"A.transport.unreachable",
			"MCP endpoint unreachable",
			findings.SeverityInfo,
			"the endpoint could not be reached: name resolution failed or the port is not accepting connections",
			truncate(msg, 300),
			"Confirm the endpoint URL (host, port, scheme), the server is running, and the network path is open.",
		)}
	}

	// Aggregated dial failure: the dialer tried multiple URLs/transports and
	// none worked. Preserve the full attempt log so the operator can see
	// exactly what the server said for each try.
	if strings.HasPrefix(msg, "mcp: dial failed after") {
		return []findings.Finding{mk(
			"A.transport.all-attempts-failed",
			"MCP endpoint rejected every transport the scanner tried",
			findings.SeverityInfo,
			"the dialer attempted both Streamable HTTP and legacy SSE across the configured probe paths; every attempt failed",
			truncate(msg, 800),
			"Verify the URL. If the server requires authentication, pass a token via the scan's headers. If the server speaks a non-standard transport, scan it via a bridge or re-run with the exact URL path.",
		)}
	}

	// Default: unknown transport/handshake failure. Preserve the raw error.
	return []findings.Finding{mk(
		"A.transport.unknown-failure",
		"MCP handshake failed",
		findings.SeverityInfo,
		"the endpoint rejected or failed the handshake in an unclassified way",
		truncate(msg, 400),
		"Inspect the raw error. Confirm the endpoint URL, scheme (https for Streamable HTTP), and whether the server speaks the MCP protocol.",
	)}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
