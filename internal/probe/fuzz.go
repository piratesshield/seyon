package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"seyon/internal/findings"
	"seyon/internal/mcp"
)

// FuzzStrategy defines a mutation to apply to tool inputs.
type FuzzStrategy struct {
	Name     string
	Class    string
	Title    string
	CWE      string
	Severity findings.Severity
	Mutate   func(schema *objectSchema) []map[string]interface{}
}

var fuzzStrategies = []FuzzStrategy{
	{
		Name:     "type-confusion",
		Class:    "F1",
		Title:    "Tool accepts type-confused input without validation",
		CWE:      "CWE-843",
		Severity: findings.SeverityMedium,
		Mutate:   typeConfusionMutations,
	},
	{
		Name:     "boundary-values",
		Class:    "F2",
		Title:    "Tool accepts extreme boundary values without validation",
		CWE:      "CWE-190",
		Severity: findings.SeverityLow,
		Mutate:   boundaryMutations,
	},
	{
		Name:     "injection-probes",
		Class:    "F3",
		Title:    "Tool does not reject injection metacharacters in input",
		CWE:      "CWE-74",
		Severity: findings.SeverityHigh,
		Mutate:   injectionMutations,
	},
	{
		Name:     "oversize-input",
		Class:    "F4",
		Title:    "Tool accepts oversized input without bounds checking",
		CWE:      "CWE-400",
		Severity: findings.SeverityLow,
		Mutate:   oversizeMutations,
	},
}

func typeConfusionMutations(schema *objectSchema) []map[string]interface{} {
	var out []map[string]interface{}
	for name, prop := range schema.Properties {
		base := baseArgs(schema)
		switch prop.Type {
		case "string":
			base[name] = 12345
			out = append(out, copyMap(base))
			base[name] = true
			out = append(out, copyMap(base))
			base[name] = []interface{}{"a", "b"}
			out = append(out, copyMap(base))
		case "integer", "number":
			base[name] = "not_a_number"
			out = append(out, copyMap(base))
			base[name] = true
			out = append(out, copyMap(base))
		case "boolean":
			base[name] = "maybe"
			out = append(out, copyMap(base))
			base[name] = 2
			out = append(out, copyMap(base))
		}
	}
	return out
}

func boundaryMutations(schema *objectSchema) []map[string]interface{} {
	var out []map[string]interface{}
	for name, prop := range schema.Properties {
		base := baseArgs(schema)
		switch prop.Type {
		case "integer", "number":
			for _, v := range []interface{}{0, -1, 2147483647, -2147483648, 9999999999999} {
				base[name] = v
				out = append(out, copyMap(base))
			}
		case "string":
			base[name] = ""
			out = append(out, copyMap(base))
		}
	}
	return out
}

func injectionMutations(schema *objectSchema) []map[string]interface{} {
	payloads := []string{
		"$(id)",
		"; ls /",
		"| cat /etc/passwd",
		"' OR '1'='1",
		"../../../etc/passwd",
		"{{7*7}}",
		"${7*7}",
		"<img src=x onerror=alert(1)>",
	}
	var out []map[string]interface{}
	for name, prop := range schema.Properties {
		if prop.Type != "string" && prop.Type != "" {
			continue
		}
		for _, payload := range payloads {
			base := baseArgs(schema)
			base[name] = payload
			out = append(out, copyMap(base))
		}
	}
	return out
}

func oversizeMutations(schema *objectSchema) []map[string]interface{} {
	var out []map[string]interface{}
	for name, prop := range schema.Properties {
		if prop.Type != "string" && prop.Type != "" {
			continue
		}
		base := baseArgs(schema)
		base[name] = strings.Repeat("A", 100000)
		out = append(out, copyMap(base))
	}
	return out
}

func baseArgs(schema *objectSchema) map[string]interface{} {
	args := map[string]interface{}{}
	for name, prop := range schema.Properties {
		args[name] = inertDefault(prop.Type)
	}
	for _, req := range schema.Required {
		if _, ok := schema.Properties[req]; !ok {
			args[req] = "seyon"
		}
	}
	return args
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// FuzzAll runs mutation-based fuzzing against all tools in the inventory.
// It only runs when active probing is authorized. Each mutation is sent as a
// tool call and the response is analyzed for error patterns that indicate
// missing validation.
func (p *Prober) FuzzAll(ctx context.Context, client *mcp.Client, inv *mcp.Inventory, endpoint string) Result {
	var res Result
	for i := range inv.Tools {
		p.fuzzTool(ctx, client, &inv.Tools[i], endpoint, &res)
	}
	findings.Sort(res.Findings)
	return res
}

func (p *Prober) fuzzTool(ctx context.Context, client *mcp.Client, tool *mcp.Tool, endpoint string, res *Result) {
	schema := parseSchema(tool.InputSchema)
	if len(schema.Properties) == 0 {
		return
	}

	maxPerStrategy := 4
	for _, strategy := range fuzzStrategies {
		mutations := strategy.Mutate(schema)
		tested := 0
		for _, args := range mutations {
			if tested >= maxPerStrategy {
				break
			}
			cctx, cancel := context.WithTimeout(ctx, callTimeout)
			out, err := client.CallTool(cctx, tool.Name, args)
			cancel()
			res.Calls++
			tested++

			if err != nil {
				continue
			}
			if out == nil {
				continue
			}

			if isFuzzFinding(strategy, out, args) {
				f := fuzzFinding(tool.Name, endpoint, strategy, args, out.Text())
				res.Findings = append(res.Findings, f)
				break
			}
		}
	}
}

func isFuzzFinding(strategy FuzzStrategy, out *mcp.CallToolResult, args map[string]interface{}) bool {
	if out.IsError {
		return false
	}
	text := out.Text()
	switch strategy.Name {
	case "injection-probes":
		for _, v := range args {
			if s, ok := v.(string); ok && len(s) > 3 {
				if strings.Contains(text, s) {
					return true
				}
			}
		}
		return false
	case "type-confusion":
		return !out.IsError
	case "oversize-input":
		return !out.IsError && len(text) > 0
	default:
		return !out.IsError
	}
}

func fuzzFinding(tool, endpoint string, strategy FuzzStrategy, args map[string]interface{}, responseText string) findings.Finding {
	argsJSON, _ := json.Marshal(args)
	f := findings.Finding{
		RuleID:     "F." + strategy.Name,
		Class:      strategy.Class,
		Title:      strategy.Title,
		Severity:   strategy.Severity,
		Confidence: findings.ConfidenceTentative,
		Modes:      []findings.Mode{findings.ModeBlack},
		Target:     findings.Target{Tool: tool, Endpoint: endpoint},
		Evidence: findings.Evidence{
			Note:     fmt.Sprintf("tool %q accepted %s mutation without error — the server did not reject malformed input, indicating missing input validation", tool, strategy.Name),
			Request:  fmt.Sprintf("CallTool(%q, %s)", tool, truncate(string(argsJSON), 300)),
			Response: truncate(responseText, 300),
		},
		CWE:         strategy.CWE,
		References:  []string{"mutation-fuzzing"},
		Remediation: "Implement strict input validation. Reject unexpected types, enforce length limits, and sanitize special characters.",
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return f
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
