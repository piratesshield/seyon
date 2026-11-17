package findings

// OWASP is an OWASP MCP Top 10 entry identifier.
type OWASP string

const (
	MCP01 OWASP = "MCP01" // Tool Poisoning
	MCP02 OWASP = "MCP02" // Prompt Injection
	MCP03 OWASP = "MCP03" // Excessive Permissions
	MCP04 OWASP = "MCP04" // Tool Shadowing
	MCP05 OWASP = "MCP05" // Unauthorized Access
	MCP06 OWASP = "MCP06" // Data Exfiltration
	MCP07 OWASP = "MCP07" // Schema Manipulation
	MCP08 OWASP = "MCP08" // Rug Pull / Tool Drift
	MCP09 OWASP = "MCP09" // Supply Chain
	MCP10 OWASP = "MCP10" // Insecure Transport
)

// OWASPEntry describes one OWASP MCP Top 10 entry.
type OWASPEntry struct {
	ID    OWASP
	Title string
	URL   string
}

var owaspEntries = map[OWASP]OWASPEntry{
	MCP01: {MCP01, "Tool Poisoning", "https://owasp.org/www-project-top-10-for-mcp/#MCP01"},
	MCP02: {MCP02, "Prompt Injection", "https://owasp.org/www-project-top-10-for-mcp/#MCP02"},
	MCP03: {MCP03, "Excessive Permissions", "https://owasp.org/www-project-top-10-for-mcp/#MCP03"},
	MCP04: {MCP04, "Tool Shadowing", "https://owasp.org/www-project-top-10-for-mcp/#MCP04"},
	MCP05: {MCP05, "Unauthorized Access", "https://owasp.org/www-project-top-10-for-mcp/#MCP05"},
	MCP06: {MCP06, "Data Exfiltration", "https://owasp.org/www-project-top-10-for-mcp/#MCP06"},
	MCP07: {MCP07, "Schema Manipulation", "https://owasp.org/www-project-top-10-for-mcp/#MCP07"},
	MCP08: {MCP08, "Rug Pull / Tool Drift", "https://owasp.org/www-project-top-10-for-mcp/#MCP08"},
	MCP09: {MCP09, "Supply Chain", "https://owasp.org/www-project-top-10-for-mcp/#MCP09"},
	MCP10: {MCP10, "Insecure Transport", "https://owasp.org/www-project-top-10-for-mcp/#MCP10"},
}

// LookupOWASP returns the entry for an OWASP identifier.
func LookupOWASP(id OWASP) (OWASPEntry, bool) {
	e, ok := owaspEntries[id]
	return e, ok
}

// classOWASP maps Seyon finding classes to OWASP MCP Top 10 entries.
var classOWASP = map[string][]OWASP{
	"B1":  {MCP01, MCP02}, // tool/prompt poisoning → Tool Poisoning + Prompt Injection
	"B2":  {MCP01},        // hidden characters → Tool Poisoning
	"B3":  {MCP04},        // tool shadowing → Tool Shadowing
	"B5":  {MCP07},        // weak schema → Schema Manipulation
	"B6":  {MCP03},        // excessive capability → Excessive Permissions
	"B7":  {MCP09},        // risky launch config → Supply Chain
	"B8":  {MCP01, MCP02}, // encoded payload evasion → Tool Poisoning + Prompt Injection
	"B9":  {MCP07, MCP01}, // full-schema poisoning → Schema Manipulation + Tool Poisoning
	"B10": {MCP01, MCP02}, // agent skill injection → Tool Poisoning + Prompt Injection
	"C1":  {MCP01, MCP05}, // command injection sink → Tool Poisoning + Unauthorized Access
	"C2":  {MCP05},        // path traversal sink → Unauthorized Access
	"C3":  {MCP06},        // SSRF sink → Data Exfiltration
	"C4":  {MCP05},        // SQL injection sink → Unauthorized Access
	"C5":  {MCP09},        // hardcoded secrets → Supply Chain
	"C6":  {MCP05},        // missing auth → Unauthorized Access
	"C7":  {MCP06, MCP03}, // toxic flow (lethal trifecta) → Data Exfiltration + Excessive Permissions
	"D1":  {MCP09},        // known vulnerable dependency
	"D2":  {MCP09},        // advisory match
	"D3":  {MCP09},        // Dockerfile risk
	"D4":  {MCP09},        // known-threat server match
	"E":   {MCP01},        // runtime reflection (canary)
	"F1":  {MCP07},        // type confusion → Schema Manipulation
	"F2":  {MCP07},        // boundary values → Schema Manipulation
	"F3":  {MCP01, MCP05}, // injection metacharacters → Tool Poisoning + Unauthorized Access
	"F4":  {MCP07},        // oversize input → Schema Manipulation
	"X":   {},             // cross-mode correlation — inherits from members
	"DR":  {MCP08},        // drift/rug-pull
}

// OWASPForClass returns the OWASP MCP Top 10 entries relevant to a finding class.
func OWASPForClass(class string) []OWASP {
	return classOWASP[class]
}
