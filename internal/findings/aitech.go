package findings

import "strings"

// AITechMapping is the Cisco AI Threat taxonomy enrichment for a finding. It
// maps a Seyon rule to the vendor-neutral AITech-X.Y / AISubtech-X.Y.Z code
// defined in Cisco's AI/Agentic Threat framework, so a Seyon JSON report can
// be ingested by any tool that already consumes Cisco AI Defense output.
//
// Reference: https://learn-cloudsecurity.cisco.com/ai-security-framework
type AITechMapping struct {
	Code         string `json:"code"`
	Name         string `json:"name"`
	SubCode      string `json:"subcode,omitempty"`
	SubName      string `json:"subname,omitempty"`
	ScannerClass string `json:"scanner_class,omitempty"`
}

// The AITech framework the vendor publishes has ~15 top-level technique
// families. Seyon only ships mappings for the subset its rules can actually
// produce today; unmapped rules return nil from AITechForRule and emit no
// aitech field in the JSON.
var (
	taxPromptInjection = AITechMapping{
		Code: "AITech-1.1", Name: "Direct Prompt Injection",
		SubCode: "AISubtech-1.1.1", SubName: "Instruction Manipulation (Direct Prompt Injection)",
		ScannerClass: "PROMPT INJECTION",
	}
	taxIndirectInjection = AITechMapping{
		Code: "AITech-1.2", Name: "Indirect Prompt Injection",
		SubCode: "AISubtech-1.2.1", SubName: "Indirect Prompt Injection via External Content",
		ScannerClass: "PROMPT INJECTION",
	}
	taxContextOverflow = AITechMapping{
		Code: "AITech-4.1", Name: "Denial of Service",
		SubCode: "AISubtech-4.1.1", SubName: "Context Window Overflow",
		ScannerClass: "DENIAL OF SERVICE",
	}
	taxDataExfil = AITechMapping{
		Code: "AITech-8.2", Name: "Data Exfiltration / Exposure",
		SubCode: "AISubtech-8.2.3", SubName: "Data Exfiltration via Agent Tooling",
		ScannerClass: "SECURITY VIOLATION",
	}
	taxSensitiveInfoDisclosure = AITechMapping{
		Code: "AITech-8.2", Name: "Data Exfiltration / Exposure",
		SubCode: "AISubtech-8.2.1", SubName: "Sensitive Information Disclosure",
		ScannerClass: "SECURITY VIOLATION",
	}
	taxUnauthSystemAccess = AITechMapping{
		Code: "AITech-9.1", Name: "Model or Agentic System Manipulation",
		SubCode: "AISubtech-9.1.2", SubName: "Unauthorized or Unsolicited System Access",
		ScannerClass: "SYSTEM MANIPULATION",
	}
	taxUnauthNetworkAccess = AITechMapping{
		Code: "AITech-9.1", Name: "Model or Agentic System Manipulation",
		SubCode: "AISubtech-9.1.3", SubName: "Unauthorized or Unsolicited Network Access",
		ScannerClass: "SSRF",
	}
	taxInjectionAttack = AITechMapping{
		Code: "AITech-9.1", Name: "Model or Agentic System Manipulation",
		SubCode: "AISubtech-9.1.4", SubName: "Injection Attacks (SQL, Command Execution, XSS)",
		ScannerClass: "INJECTION ATTACK",
	}
	taxSupplyChain = AITechMapping{
		Code: "AITech-9.3", Name: "Supply Chain Compromise",
		SubCode: "AISubtech-9.3.1", SubName: "Malicious Package / Tool Injection",
		ScannerClass: "VULNERABLE DEPENDENCY",
	}
	taxDefenseEvasion = AITechMapping{
		Code: "AITech-11.1", Name: "Environment-Aware Evasion",
		SubCode: "AISubtech-11.1.2", SubName: "Tool-Scoped Evasion",
		ScannerClass: "DEFENSE EVASION",
	}
	taxToolPoisoning = AITechMapping{
		Code: "AITech-12.1", Name: "Tool Exploitation",
		SubCode: "AISubtech-12.1.2", SubName: "Tool Poisoning",
		ScannerClass: "TOOL POISONING",
	}
	taxUnsafeFileExec = AITechMapping{
		Code: "AITech-12.1", Name: "Tool Exploitation",
		SubCode: "AISubtech-12.1.3", SubName: "Unsafe System / Browser / File Exec",
		ScannerClass: "ARBITRARY RESOURCE READ/WRITE",
	}
	taxToolShadowing = AITechMapping{
		Code: "AITech-12.1", Name: "Tool Exploitation",
		SubCode: "AISubtech-12.1.5", SubName: "Tool Shadowing",
		ScannerClass: "TOOL SHADOWING",
	}
	taxResourceExhaustion = AITechMapping{
		Code: "AITech-13.1", Name: "Disruption of Availability",
		SubCode: "AISubtech-13.1.1", SubName: "Compute Exhaustion",
		ScannerClass: "RESOURCE EXHAUSTION",
	}
)

// classMapping covers the default class-level taxonomy. Rule-ID overrides
// (below) take precedence when a specific rule warrants a more precise code.
var classMapping = map[string]*AITechMapping{
	// Seyon B-class (OWASP MCP Top 10)
	"B1":  &taxPromptInjection,   // tool description instruction-override
	"B2":  &taxPromptInjection,   // hidden characters / Unicode trickery in prompt
	"B3":  &taxToolShadowing,     // tool/prompt name collision / shadowing
	"B4":  &taxDataExfil,         // secret exfil channels
	"B5":  &taxInjectionAttack,   // weak input schema (injection enablement)
	"B6":  &taxUnsafeFileExec,    // tool declares file/exec capability
	"B7":  &taxSupplyChain,       // suspicious server command/args in config
	"B8":  &taxContextOverflow,   // oversized payload / context-overflow DoS
	"B9":  &taxIndirectInjection, // full-schema poisoning, retrieved-content directives
	"B10": &taxToolPoisoning,     // agent skill/hooks poisoning
	// Seyon D-class (Prompt-defense gap — missing defenses)
	"D": &taxPromptInjection,
	// Seyon P-class (protocol wire-probe findings)
	"P": &taxUnauthNetworkAccess,
	// Seyon U-class (deep unauthenticated audit — TLS, headers, CORS, OAuth
	// discovery, server fingerprint, sensitive-path disclosure). Default to
	// Unauth System Access; specific rules override below.
	"U": &taxUnauthSystemAccess,
	// Seyon F-class (active probing / fuzzing)
	"F":  &taxInjectionAttack,
	"F2": &taxInjectionAttack,
	"F3": &taxInjectionAttack,
	"F4": &taxInjectionAttack,
	// Seyon E-class (encoded payloads)
	"E": &taxDefenseEvasion,
	// Seyon R-class (readiness — operational posture, not security)
	"R": nil,
	// Seyon A-class (black-box recon of unreachable/auth-gated endpoints)
	"A": nil,
	// Seyon X-class (cross-mode correlation) — carries no taxonomy of its own.
	"X": nil,
}

// ruleOverride takes precedence over classMapping when the rule_id itself
// signals a more specific category (e.g. "B9.schema.ref-local-file" is
// unsafe-file-exec rather than generic indirect-injection).
var ruleOverride = map[string]*AITechMapping{
	// B-class rule overrides
	"B9.schema.ref-local-file":       &taxUnsafeFileExec,
	"B9.schema.ref-private-network":  &taxUnauthNetworkAccess,
	"B9.schema.ref-external-network": &taxUnauthNetworkAccess,
	// Protocol probe overrides (P-class covers transport/auth/etc)
	"P1.transport.unencrypted": &taxDataExfil,          // plaintext → eavesdrop
	"P2.auth.open":             &taxUnauthSystemAccess, // tool enum open to world
	"P3.signing.missing":       &taxToolPoisoning,      // response tamper → tool poison
	"P4.replay.unprotected":    &taxUnauthNetworkAccess,
	"P5.tools.unintegrity":     &taxToolPoisoning,
	"P6.fail-open":             &taxInjectionAttack,
	"P7.rate-limit.missing":    &taxResourceExhaustion,
	"P8.identity.spoofable":    &taxUnauthSystemAccess,
	// Prompt-defense rule overrides (D-class default = PromptInjection; some are different)
	"D2.data-leakage":       &taxSensitiveInfoDisclosure,
	"D4.indirect-injection": &taxIndirectInjection,
	"D9.context-overflow":   &taxContextOverflow,
	"D11.input-validation":  &taxInjectionAttack,
	"D12.abuse-prevention":  &taxResourceExhaustion,
}

// AITechForRule returns the AITech mapping for a rule. ruleID takes
// precedence over class. Returns nil when there is no mapping.
func AITechForRule(class, ruleID string) *AITechMapping {
	if m, ok := ruleOverride[ruleID]; ok && m != nil {
		return m
	}
	// Some rule IDs share a prefix we want to match (e.g. "F3.injection-probes"
	// should map through the F3 class key if someone passes a sub-identifier).
	if m, ok := classMapping[class]; ok && m != nil {
		return m
	}
	// Last-resort: try the first dot-prefix of the rule_id as a class.
	if dot := strings.Index(ruleID, "."); dot > 0 {
		prefix := ruleID[:dot]
		if m, ok := classMapping[prefix]; ok && m != nil {
			return m
		}
	}
	return nil
}
