package detect

import (
	"fmt"
	"regexp"
	"strings"

	"seyon/internal/findings"
	"seyon/internal/mcp"
)

// Readiness is the opposite of Severity: a tool or server description can be
// SECURE and still be unready for production. The readiness analyzer surfaces
// operational-posture gaps — missing timeouts, no retry strategy, no error-
// handling guidance, no idempotency note — that make a tool fragile even in
// the absence of a security defect.
//
// All findings are class "R" (Readiness) with Info-to-Medium severity. They
// never promote to Critical because they are not security defects.
//
// The rule set mirrors Cisco's readiness analyzer (20 operational heuristics)
// re-expressed as Go regex checks.

type readinessRule struct {
	id          string
	severity    findings.Severity
	title       string
	trigger     []*regexp.Regexp // regex whose PRESENCE indicates the tool behavior requires the defense
	defense     []*regexp.Regexp // regex whose PRESENCE indicates the defense exists
	remediation string
}

func rxCI(expr string) *regexp.Regexp { return regexp.MustCompile(`(?i)` + expr) }

var readinessRules = []readinessRule{
	// R1-R4: generic operational posture — always required.
	{
		id: "R1.timeout.missing", severity: findings.SeverityMedium,
		title:   "Tool description names no timeout",
		trigger: nil, // always applies
		defense: []*regexp.Regexp{
			rxCI(`\b(timeout|time.?out|deadline|time ?limit|maximum.{0,20}time|within \d+\s*(ms|s|second|minute))\b`),
			rxCI(`\b\d+\s*(ms|s|seconds?|minutes?)\b.*\b(limit|max|cap)\b`),
		},
		remediation: "State a hard per-call timeout. An agent that cannot bound tool latency cannot be run in a production loop.",
	},
	{
		id: "R2.retry.missing", severity: findings.SeverityLow,
		title:   "Tool description names no retry strategy",
		trigger: nil,
		defense: []*regexp.Regexp{
			rxCI(`\b(retry|retries|exponential ?backoff|back ?off|jitter|retry.?after)\b`),
			rxCI(`\b(idempotent|safe to (re)?run|re.?runnable)\b`),
		},
		remediation: "Say whether the tool is safe to retry and under what conditions. Retry policy prevents double-bookings on transient 5xx responses.",
	},
	{
		id: "R3.error-handling.unspecified", severity: findings.SeverityMedium,
		title:   "Tool description names no error-handling behavior",
		trigger: nil,
		defense: []*regexp.Regexp{
			rxCI(`\b(error|failure|exception|returns? (null|empty|an error|error object))\b`),
			rxCI(`\b(status ?code|http \d|\d{3} error|try.?catch|graceful|fallback)\b`),
		},
		remediation: "Document what the tool returns on failure: an exception, an empty result, or a structured error object. An agent cannot recover from an unspecified failure shape.",
	},
	{
		id: "R4.idempotency.unstated", severity: findings.SeverityLow,
		title:   "Tool description does not state idempotency",
		trigger: nil,
		defense: []*regexp.Regexp{
			rxCI(`\b(idempotent|safe to (re)?run|re.?runnable|no.?side.?effects?|read.?only)\b`),
			rxCI(`\b(dedup(e|licat)|dedupe|request id|idempotency key)\b`),
		},
		remediation: "State whether calling the tool twice with the same input is safe. Agents that retry blindly can double-charge, double-send, or double-create.",
	},

	// R5-R10: trigger-conditional — only fire when the tool claims to do
	// something that WOULD benefit from the defense.

	{
		id: "R5.pagination.unbounded", severity: findings.SeverityLow,
		title: "Tool returns a list but names no pagination control",
		trigger: []*regexp.Regexp{
			rxCI(`\b(list|enumerate|returns.{0,20}(list|array|collection|rows|items|records))\b`),
		},
		defense: []*regexp.Regexp{
			rxCI(`\b(paginat|page|offset|cursor|limit|chunk|batch)\b`),
		},
		remediation: "Add a paginated interface (cursor or limit). Unbounded list output is the most common DoS path through a working MCP server.",
	},
	{
		id: "R6.network.no-tls", severity: findings.SeverityMedium,
		title: "Tool makes network calls but does not state TLS / verification",
		trigger: []*regexp.Regexp{
			rxCI(`\b(http (call|request)|fetch|external api|remote (call|service)|webhook|rest)\b`),
		},
		defense: []*regexp.Regexp{
			rxCI(`\b(https?://|tls|ssl|verif(y|ied)|certificate)\b`),
		},
		remediation: "Document which hosts the tool talks to and whether TLS certificate verification is enforced. Unverified HTTPS is as weak as plaintext.",
	},
	{
		id: "R7.db.no-txn", severity: findings.SeverityLow,
		title: "Tool writes to a data store but does not state transactionality",
		trigger: []*regexp.Regexp{
			rxCI(`\b(write to|insert|update|delete|upsert|modify).{0,40}\b(database|db|table|collection|record)\b`),
		},
		defense: []*regexp.Regexp{
			rxCI(`\b(transaction|txn|atomic|rollback|commit|savepoint)\b`),
		},
		remediation: "Say whether writes are atomic. A multi-row tool that partially fails and silently commits is the classic MCP corruption bug.",
	},
	{
		id: "R8.auth.unstated", severity: findings.SeverityMedium,
		title: "Tool description does not describe its auth model",
		trigger: []*regexp.Regexp{
			rxCI(`\b(authenticated|login|credential|token|api key|session)\b`),
		},
		defense: []*regexp.Regexp{
			rxCI(`\b(requires|provided by|managed by|server-?side|user-?scoped|oauth|bearer)\b`),
		},
		remediation: "Say whose credential the tool uses (caller's, server's, user-scoped OAuth) and where it comes from. Blind credential inheritance is how tokens leak.",
	},
	{
		id: "R9.observability.unmentioned", severity: findings.SeverityInfo,
		title:   "Tool description does not mention logging or tracing",
		trigger: nil,
		defense: []*regexp.Regexp{
			rxCI(`\b(log|logs|logging|trace|tracing|metric|audit|request.?id|correlation ?id)\b`),
		},
		remediation: "Mention that the tool emits structured logs / traces per call. Observability is a prerequisite for debugging agent behaviour in production.",
	},
	{
		id: "R10.file-size.unbounded", severity: findings.SeverityLow,
		title: "Tool accepts a file but does not state a size limit",
		trigger: []*regexp.Regexp{
			rxCI(`\b(file|upload|attachment|document|image|archive)\b`),
		},
		defense: []*regexp.Regexp{
			rxCI(`\b((max|maximum) (size|bytes|mb|kb)|size (limit|cap)|\d+\s*(mb|kb|gb)\b)`),
		},
		remediation: "Declare the max size the tool accepts. Unbounded file inputs cause memory pressure and open an easy DoS vector.",
	},

	// R11-R15: safety heuristics for destructive / irreversible operations.
	{
		id: "R11.destructive.no-confirm", severity: findings.SeverityMedium,
		title: "Destructive operation with no confirmation token",
		trigger: []*regexp.Regexp{
			rxCI(`\b(delete|remove|drop|wipe|purge|truncate|destroy)\b`),
		},
		defense: []*regexp.Regexp{
			rxCI(`\b(confirm(ation)?|dry.?run|preview|token|reversible|soft.?delete|archived?)\b`),
		},
		remediation: "Require a confirmation flag or dry-run mode for destructive tools. Agents misinterpret delete requests with alarming frequency.",
	},
	{
		id: "R12.money.no-limit", severity: findings.SeverityMedium,
		title: "Tool moves money but does not state limits",
		trigger: []*regexp.Regexp{
			rxCI(`\b(payment|charge|refund|transfer|wire|invoice|checkout|purchase|withdrawal|deposit)\b`),
		},
		defense: []*regexp.Regexp{
			rxCI(`\b((max|cap|limit).{0,40}(amount|value|\$|usd|eur|gbp)|daily cap|per.?transaction limit)\b`),
		},
		remediation: "State per-call and per-day monetary caps. This is the last line of defense against prompt-injected financial loss.",
	},
	{
		id: "R13.destructive.no-undo", severity: findings.SeverityLow,
		title: "Destructive operation does not state undo window",
		trigger: []*regexp.Regexp{
			rxCI(`\b(delete|remove|archive|destroy|purge)\b`),
		},
		defense: []*regexp.Regexp{
			rxCI(`\b(undo|restore|trash|recycle|retention|soft.?delete|within \d+\s*(hour|day))\b`),
		},
		remediation: "If the tool is destructive, document the undo / retention window. 30-day soft-delete is the industry norm for user-visible data.",
	},
	{
		id: "R14.schema.unversioned", severity: findings.SeverityInfo,
		title:   "Tool description names no schema version",
		trigger: nil,
		defense: []*regexp.Regexp{
			rxCI(`\b(version|v\d+(\.\d+)*|schema.?version|api.?version)\b`),
		},
		remediation: "Include a version marker in the tool name or description. Agents that cache schemas need to know when a server-side schema change happened.",
	},
	{
		id: "R15.scope.unbounded", severity: findings.SeverityMedium,
		title: "Tool operates across all users/accounts without scope",
		trigger: []*regexp.Regexp{
			rxCI(`\b(all (users|accounts|tenants|customers)|any (user|account|tenant|customer)|org.?wide|tenant.?wide)\b`),
		},
		defense: []*regexp.Regexp{
			rxCI(`\b(scope(d)?|restrict|limit|filter|role|permission|rbac)\b`),
		},
		remediation: "Scope the tool to a single tenant/user by default. A cross-tenant tool invoked by a compromised agent is a lateral-movement primitive.",
	},

	// R16-R20: rate-limit, caching, async, streaming, resource lifecycle.
	{
		id: "R16.rate-limit.unstated", severity: findings.SeverityLow,
		title:   "Tool does not declare caller-side rate limits",
		trigger: nil,
		defense: []*regexp.Regexp{
			rxCI(`\b(rate.?limit|throttl|quota|per (second|minute|hour)|\d+/\s*(s|sec|min|hour))\b`),
		},
		remediation: "Say what the per-caller rate limit is. An agent that does not know the limit will trip it, then retry blindly, then trip it again.",
	},
	{
		id: "R17.cache.unspecified", severity: findings.SeverityInfo,
		title: "Tool does not describe its caching behavior",
		trigger: []*regexp.Regexp{
			rxCI(`\b(get|fetch|read|lookup|query|retrieve)\b`),
		},
		defense: []*regexp.Regexp{
			rxCI(`\b(cache|cach(ed|ing)|ttl|stale|fresh|etag|if-?none-?match|cache.?control)\b`),
		},
		remediation: "If the tool is read-only, document its cache TTL. Agents will otherwise repeat identical calls at compute cost with no benefit.",
	},
	{
		id: "R18.async.no-polling-shape", severity: findings.SeverityLow,
		title: "Tool is asynchronous but does not describe how to check status",
		trigger: []*regexp.Regexp{
			rxCI(`\b(async|asynchronous|returns (a )?(task|job|operation)( id)?|long.?running)\b`),
		},
		defense: []*regexp.Regexp{
			rxCI(`\b(poll|status|job id|operation id|webhook|callback|promise|awaits?)\b`),
		},
		remediation: "An async tool must document how to retrieve the result (polling URL, webhook, callback). Otherwise the result is unreachable to the agent.",
	},
	{
		id: "R19.streaming.unmentioned", severity: findings.SeverityInfo,
		title: "Tool may return large output but does not mention streaming",
		trigger: []*regexp.Regexp{
			rxCI(`\b(large|long|big|many|thousands|streaming|stream.?able)\b`),
		},
		defense: []*regexp.Regexp{
			rxCI(`\b(stream(ing|s)?|chunk(ed)?|sse|server-?sent|flush|partial)\b`),
		},
		remediation: "Document whether the response is streamed or buffered. A tool that buffers megabytes of output causes the agent to hit its own context cap.",
	},
	{
		id: "R20.resource.lifecycle-unclear", severity: findings.SeverityInfo,
		title: "Tool creates a resource but does not describe its lifecycle",
		trigger: []*regexp.Regexp{
			rxCI(`\b(creates? (a|an|the)|allocates?|provisions?|generates? a new|new (resource|handle|session))\b`),
		},
		defense: []*regexp.Regexp{
			rxCI(`\b(expir|ttl|cleanup|release|dispose|lifetime|retention|auto.?delete)\b`),
		},
		remediation: "Say how long created resources live and who cleans them up. Agents that create without cleaning leak resources indefinitely.",
	},
}

// scanReadiness runs every readiness rule against a text block. It is the
// readiness analog of scanPromptDefenses: for each rule whose trigger fires
// but defense pattern is missing, it emits one Info/Low/Medium finding under
// class "R". Rules with no trigger always fire the check.
func scanReadiness(text, kind, name, origin string) []findings.Finding {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var out []findings.Finding
	for _, rule := range readinessRules {
		// Trigger must match (if any). Rules with no trigger always evaluate.
		triggered := len(rule.trigger) == 0
		if !triggered {
			for _, re := range rule.trigger {
				if re.MatchString(text) {
					triggered = true
					break
				}
			}
		}
		if !triggered {
			continue
		}

		// Defense must be present.
		defPresent := false
		for _, re := range rule.defense {
			if re.MatchString(text) {
				defPresent = true
				break
			}
		}
		if defPresent {
			continue
		}

		f := findings.Finding{
			RuleID:     rule.id,
			Class:      "R",
			Title:      rule.title,
			Severity:   rule.severity,
			Confidence: findings.ConfidenceTentative,
			Modes:      []findings.Mode{findings.ModeBlack, findings.ModeGray},
			Target:     findings.Target{Tool: name, Endpoint: origin},
			Evidence: findings.Evidence{
				Note: fmt.Sprintf(
					"%s %q lacks operational posture for %s — this is a production-readiness concern, not a security defect",
					kind, name, rule.id,
				),
			},
			CWE:         "",
			References:  []string{"readiness", kind},
			Remediation: rule.remediation,
			StageStatus: findings.StageCompleted,
		}
		f.ID = f.Fingerprint()
		out = append(out, f)
	}
	return out
}

// Readiness scans every tool declared on the surface and emits R-class
// findings. Called separately from Surface() so a caller can opt out of
// readiness-vs-security noise.
func (a *Analyzer) Readiness(s *surfacedTools) []findings.Finding {
	var out []findings.Finding
	for _, t := range s.tools {
		out = append(out, scanReadiness(t.Description, "tool.description", t.Name, s.origin)...)
	}
	return out
}

// surfacedTools is a tiny structural adapter so Readiness() doesn't depend on
// the full surface.Surface type (which would introduce an import cycle for
// callers who only have mcp.Tool slices).
type surfacedTools struct {
	tools  []mcp.Tool
	origin string
}

// ReadinessOnTools is the convenience constructor callers use.
func (a *Analyzer) ReadinessOnTools(tools []mcp.Tool, origin string) []findings.Finding {
	return a.Readiness(&surfacedTools{tools: tools, origin: origin})
}
