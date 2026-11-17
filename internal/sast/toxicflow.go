package sast

import (
	"go/ast"
	"go/token"

	"seyon/internal/findings"
)

// Toxic flow analysis: the "lethal trifecta" detector.
//
// A function is a toxic flow when it combines ALL THREE of:
//   1. Untrusted input source (function parameters, request body, user input)
//   2. Private/sensitive data access (file reads, database queries, env vars)
//   3. Network egress (HTTP requests, socket writes, external calls)
//
// When all three are present in a single function, an attacker-controlled input
// can reach private data and then exfiltrate it over the network. This is the
// most dangerous pattern in MCP tool handlers.

// callCategory classifies function/method calls by their security role.
type callCategory int

const (
	catNone   callCategory = 0
	catInput  callCategory = 1 << iota // untrusted input source
	catData                            // private/sensitive data access
	catEgress                          // network egress
)

type callClassifier struct {
	pkg, fn  string
	category callCategory
}

var goCallClassifiers = []callClassifier{
	// Input sources: parameters are already tainted; these are explicit input reads
	{"io", "ReadAll", catInput},
	{"ioutil", "ReadAll", catInput},
	{"json", "Unmarshal", catInput},
	{"json", "Decode", catInput},
	{"json", "NewDecoder", catInput},

	// Data access: file system, database, environment
	{"os", "ReadFile", catData},
	{"os", "Open", catData},
	{"os", "OpenFile", catData},
	{"os", "ReadDir", catData},
	{"os", "Getenv", catData},
	{"ioutil", "ReadFile", catData},
	{"ioutil", "ReadDir", catData},

	// Network egress
	{"http", "Get", catEgress},
	{"http", "Post", catEgress},
	{"http", "PostForm", catEgress},
	{"http", "NewRequest", catEgress},
	{"http", "NewRequestWithContext", catEgress},
}

// SQL methods count as data access.
var dataMethods = map[string]bool{
	"Query": true, "QueryContext": true, "QueryRow": true, "QueryRowContext": true,
	"Exec": true, "ExecContext": true,
	"Find": true, "First": true, "Where": true, // ORM methods
}

var egressMethods = map[string]bool{
	"Do": true, "Send": true, "Write": true, "Dial": true,
	"DialContext": true, "RoundTrip": true,
}

func checkToxicFlow(fset *token.FileSet, rel string, fn *ast.FuncDecl, reg *toolRegistry) (findings.Finding, bool) {
	var hasInput, hasData, hasEgress bool
	var inputEvidence, dataEvidence, egressEvidence string

	hasParams := fn.Type.Params != nil && len(fn.Type.Params.List) > 0
	if hasParams {
		hasInput = true
		inputEvidence = "function parameters"
	}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			methodName := fun.Sel.Name
			if id, ok := fun.X.(*ast.Ident); ok {
				pkgName := id.Name
				for _, cc := range goCallClassifiers {
					if pkgName == cc.pkg && methodName == cc.fn {
						switch cc.category {
						case catInput:
							hasInput = true
							inputEvidence = pkgName + "." + methodName
						case catData:
							hasData = true
							dataEvidence = pkgName + "." + methodName
						case catEgress:
							hasEgress = true
							egressEvidence = pkgName + "." + methodName
						}
					}
				}
			}
			if dataMethods[methodName] {
				hasData = true
				if dataEvidence == "" {
					dataEvidence = "." + methodName + "()"
				}
			}
			if egressMethods[methodName] {
				hasEgress = true
				if egressEvidence == "" {
					egressEvidence = "." + methodName + "()"
				}
			}
		}
		return true
	})

	if !hasInput || !hasData || !hasEgress {
		return findings.Finding{}, false
	}

	pos := fset.Position(fn.Pos())
	source := rel
	if pos.Line > 0 {
		source = rel + ":" + itoa(pos.Line)
	}

	toolName := ""
	if reg != nil {
		toolName = reg.toolForFunc(fn.Name.Name)
	}

	f := findings.Finding{
		RuleID:   "C7.toxicflow",
		Class:    "C7",
		Title:    "Toxic flow: untrusted input + private data + network egress",
		Severity: findings.SeverityCritical,
		Confidence: func() findings.Confidence {
			if toolName != "" {
				return findings.ConfidenceFirm
			}
			return findings.ConfidenceTentative
		}(),
		Modes:  []findings.Mode{findings.ModeWhite},
		Target: findings.Target{Tool: toolName, Source: source},
		Evidence: findings.Evidence{
			Note: "LETHAL TRIFECTA in func " + fn.Name.Name + "() at " + source + ":\n" +
				"  1. UNTRUSTED INPUT: " + inputEvidence + " (user-controlled data enters the function)\n" +
				"  2. PRIVATE DATA ACCESS: " + dataEvidence + " (function reads sensitive data)\n" +
				"  3. NETWORK EGRESS: " + egressEvidence + " (function sends data over the network)\n" +
				"An attacker can craft input that reads private data and exfiltrates it via the network call.",
		},
		CWE:         "CWE-200",
		Remediation: "Separate data access from network operations. Use an allowlist for egress destinations. Never pass untrusted input directly to both data reads and network sends.",
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return f, true
}
