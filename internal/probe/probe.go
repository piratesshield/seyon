// Package probe is Seyon's active black-box prober. It runs only when active
// probing has been authorized by a scope file. Its one technique is an inert
// canary: a random, benign marker is passed as a tool argument and the response
// is checked for the marker. That confirms, at runtime, that caller-supplied
// input flows into the tool's output — the dataflow substrate for tool-output
// injection — without sending any exploit, shell metacharacter, traversal
// sequence, or destructive payload. The prober never attempts exploitation.
package probe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"seyon/internal/findings"
	"seyon/internal/mcp"
)

// defaultMaxCallsPerTool bounds invocations per tool when the scope does not set
// a limit, so probing never becomes a load test.
const defaultMaxCallsPerTool = 4

// callTimeout bounds a single tool invocation.
const callTimeout = 15 * time.Second

// Prober invokes tools with inert canaries. Zero value is not usable; use New.
type Prober struct {
	maxCalls int
}

// New builds a prober. maxCalls <= 0 selects the built-in default.
func New(maxCalls int) *Prober {
	if maxCalls <= 0 {
		maxCalls = defaultMaxCallsPerTool
	}
	return &Prober{maxCalls: maxCalls}
}

// newCanary returns a fresh inert marker. It is plain [a-f0-9], so it can never
// act as a metacharacter, path, or code.
func newCanary() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "seyoncanary" + hex.EncodeToString(b[:])
}

// objectSchema is the minimal slice of a JSON Schema the prober reads: an
// object's properties (with their types) and its required list.
type objectSchema struct {
	Type       string                    `json:"type"`
	Properties map[string]propertySchema `json:"properties"`
	Required   []string                  `json:"required"`
}

type propertySchema struct {
	Type string `json:"type"`
}

func parseSchema(raw json.RawMessage) *objectSchema {
	if len(raw) == 0 {
		return &objectSchema{Type: "object"}
	}
	var s objectSchema
	if err := json.Unmarshal(raw, &s); err != nil {
		return &objectSchema{Type: "object"}
	}
	return &s
}

// inertDefault returns a benign value for a non-canary field, by JSON type.
func inertDefault(t string) interface{} {
	switch t {
	case "integer", "number":
		return 0
	case "boolean":
		return false
	case "array":
		return []interface{}{}
	case "object":
		return map[string]interface{}{}
	default:
		return "seyon"
	}
}

// Result reports what the prober observed for one target.
type Result struct {
	Findings []findings.Finding
	Calls    int // number of tool invocations actually made
}

// ProbeAll probes every tool in the inventory that declares a string input,
// sending one inert canary per string property (bounded per tool). Tools with
// no string input are skipped (nothing to reflect).
func (p *Prober) ProbeAll(ctx context.Context, client *mcp.Client, inv *mcp.Inventory, endpoint string) Result {
	var res Result
	for i := range inv.Tools {
		p.probeTool(ctx, client, &inv.Tools[i], endpoint, &res)
	}
	findings.Sort(res.Findings)
	return res
}

func (p *Prober) probeTool(ctx context.Context, client *mcp.Client, tool *mcp.Tool, endpoint string, res *Result) {
	schema := parseSchema(tool.InputSchema)
	var stringFields []string
	for name, prop := range schema.Properties {
		if prop.Type == "string" || prop.Type == "" {
			stringFields = append(stringFields, name)
		}
	}
	// A tool with no declared string input offers no inert-canary surface.
	if len(stringFields) == 0 {
		return
	}

	calls := 0
	reported := false
	for _, field := range stringFields {
		if calls >= p.maxCalls || reported {
			break
		}
		canary := newCanary()
		args := map[string]interface{}{}
		for name, prop := range schema.Properties {
			args[name] = inertDefault(prop.Type)
		}
		for _, req := range schema.Required {
			if _, ok := schema.Properties[req]; !ok {
				args[req] = "seyon"
			}
		}
		args[field] = canary

		cctx, cancel := context.WithTimeout(ctx, callTimeout)
		out, err := client.CallTool(cctx, tool.Name, args)
		cancel()
		calls++
		res.Calls++
		if err != nil || out == nil || out.IsError {
			continue // the tool rejected the input; not a finding
		}
		if strings.Contains(out.Text(), canary) {
			res.Findings = append(res.Findings, reflectionFinding(tool.Name, field, endpoint))
			reported = true // one confirmation per tool is enough
		}
	}
}

func reflectionFinding(tool, field, endpoint string) findings.Finding {
	f := findings.Finding{
		RuleID:     "E.tool-reflects-input",
		Class:      "E",
		Title:      "Tool reflects caller-supplied input into its output (runtime-confirmed)",
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceConfirmed,
		Modes:      []findings.Mode{findings.ModeBlack},
		Target:     findings.Target{Tool: tool, Endpoint: endpoint},
		Evidence: findings.Evidence{
			Note:    fmt.Sprintf("tool %q reflects caller input: an inert canary marker sent in argument %q appeared verbatim in the response — this confirms caller-supplied input flows into tool output, enabling tool-output injection", tool, field),
			Request: fmt.Sprintf("CallTool(%q, {%q: %q, ...})", tool, field, "<canary-marker>"),
		},
		CWE:         "CWE-74",
		References:  []string{"runtime-canary", "tool-output-injection"},
		Remediation: "Treat tool output as attacker-influenced in the agent. Sanitize or encode reflected input, and do not let a tool echo untrusted content into agent-visible channels without review.",
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return f
}
