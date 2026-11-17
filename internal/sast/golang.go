package sast

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"

	"seyon/internal/findings"
)

// goSink describes a dangerous standard-library call and the finding class it
// maps to. argIdx is the argument to test for untrusted input; -1 means test
// every argument.
type goSink struct {
	pkg, fn  string
	class    string
	cwe      string
	title    string
	argIdx   int
	severity findings.Severity
}

var goSinks = []goSink{
	{"exec", "Command", "C1", "CWE-78", "Command executed from untrusted input", -1, findings.SeverityCritical},
	{"exec", "CommandContext", "C1", "CWE-78", "Command executed from untrusted input", -1, findings.SeverityCritical},
	{"os", "ReadFile", "C2", "CWE-22", "File read from an untrusted path", 0, findings.SeverityHigh},
	{"os", "Open", "C2", "CWE-22", "File opened from an untrusted path", 0, findings.SeverityHigh},
	{"os", "OpenFile", "C2", "CWE-22", "File opened from an untrusted path", 0, findings.SeverityHigh},
	{"ioutil", "ReadFile", "C2", "CWE-22", "File read from an untrusted path", 0, findings.SeverityHigh},
	{"http", "Get", "C3", "CWE-918", "URL fetched from untrusted input (SSRF)", 0, findings.SeverityHigh},
	{"http", "Post", "C3", "CWE-918", "URL fetched from untrusted input (SSRF)", 0, findings.SeverityHigh},
	{"http", "NewRequest", "C3", "CWE-918", "URL fetched from untrusted input (SSRF)", 1, findings.SeverityHigh},
	{"http", "NewRequestWithContext", "C3", "CWE-918", "URL fetched from untrusted input (SSRF)", 2, findings.SeverityHigh},
}

// sqlMethods maps database/sql method names to the index of the query argument.
// Non-Context variants have the query at arg 0; Context variants at arg 1.
var sqlMethods = map[string]int{
	"Query": 0, "QueryRow": 0, "Exec": 0,
	"QueryContext": 1, "QueryRowContext": 1, "ExecContext": 1,
}

var authKeywords = []string{
	"auth", "authorize", "authoriz", "permission", "authenticate",
	"verifytoken", "checkaccess", "currentuser", "principal", "entitlement", "rbac",
}

// goSource is one Go file gathered during the directory walk, analyzed as part
// of the whole tree so tool registrations in one file can anchor sinks in
// another.
type goSource struct {
	rel  string
	data []byte
}

// analyzeGo parses and analyzes a single Go file with no cross-file tool
// registry. It is retained for single-file callers and fuzzing.
func analyzeGo(rel string, src []byte) []findings.Finding {
	return analyzeGoTree([]goSource{{rel: rel, data: src}})
}

// analyzeGoTree reports C1–C4 and C6 findings across a set of Go files using an
// intra-function, name-based taint approximation (a value is tainted if it
// derives from a function parameter). It first builds a tree-wide registry of
// MCP tool handlers, then stamps each finding with the tool its handler
// implements, so white-box findings can correlate with gray/black ones.
func analyzeGoTree(sources []goSource) []findings.Finding {
	type parsedFile struct {
		rel  string
		fset *token.FileSet
		file *ast.File
		src  []byte
	}
	var parsed []parsedFile
	reg := newToolRegistry()
	for _, s := range sources {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, s.rel, s.data, 0)
		if err != nil {
			continue // not parseable; the pattern engine does not run on Go
		}
		parsed = append(parsed, parsedFile{rel: s.rel, fset: fset, file: file, src: s.data})
		reg.collect(s.rel, file)
	}

	var out []findings.Finding
	for _, p := range parsed {
		for _, decl := range p.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			fa := &funcAnalysis{fset: p.fset, rel: p.rel, src: p.src, fn: fn, reg: reg}
			fa.computeTaint()
			out = append(out, fa.scanSinks()...)
			if tf, ok := checkToxicFlow(p.fset, p.rel, fn, reg); ok {
				out = append(out, tf)
			}
		}
	}
	return out
}

type funcAnalysis struct {
	fset    *token.FileSet
	rel     string
	src     []byte
	fn      *ast.FuncDecl
	reg     *toolRegistry
	tainted map[string]bool
	hasSink bool
}

// toolFor resolves the MCP tool a finding belongs to: the tool implemented by
// the enclosing named handler, or the tool of an inline-closure handler that
// encloses node n. It returns "" when the code is not a registered handler.
func (fa *funcAnalysis) toolFor(n ast.Node) string {
	if fa.reg == nil {
		return ""
	}
	if t := fa.reg.toolForFunc(fa.fn.Name.Name); t != "" {
		return t
	}
	return fa.reg.toolForNode(fa.rel, n)
}

// text renders a node's source, whitespace-collapsed and truncated.
func (fa *funcAnalysis) text(n ast.Node) string {
	start := fa.fset.Position(n.Pos()).Offset
	end := fa.fset.Position(n.End()).Offset
	if start < 0 || end > len(fa.src) || start >= end {
		return ""
	}
	s := strings.Join(strings.Fields(string(fa.src[start:end])), " ")
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

// computeTaint seeds taint with the function's parameters, then propagates it
// across assignments to a fixed point (bounded).
func (fa *funcAnalysis) computeTaint() {
	fa.tainted = map[string]bool{}
	if fa.fn.Type.Params != nil {
		for _, p := range fa.fn.Type.Params.List {
			for _, n := range p.Names {
				if n.Name != "_" {
					fa.tainted[n.Name] = true
				}
			}
		}
	}
	for pass := 0; pass < 5; pass++ {
		changed := false
		ast.Inspect(fa.fn.Body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				if fa.referencesTaintedList(s.Rhs) {
					for _, lhs := range s.Lhs {
						if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" && !fa.tainted[id.Name] {
							fa.tainted[id.Name] = true
							changed = true
						}
					}
				}
			case *ast.ValueSpec:
				if fa.referencesTaintedList(s.Values) {
					for _, id := range s.Names {
						if id.Name != "_" && !fa.tainted[id.Name] {
							fa.tainted[id.Name] = true
							changed = true
						}
					}
				}
			}
			return true
		})
		if !changed {
			break
		}
	}
}

func (fa *funcAnalysis) referencesTaintedList(exprs []ast.Expr) bool {
	for _, e := range exprs {
		if fa.referencesTainted(e) {
			return true
		}
	}
	return false
}

// referencesTainted reports whether expr reads any tainted identifier.
func (fa *funcAnalysis) referencesTainted(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && fa.tainted[id.Name] {
			found = true
			return false
		}
		return true
	})
	return found
}

// isConstArg reports whether an argument is a plain literal (safe).
func isConstArg(e ast.Expr) bool {
	_, ok := e.(*ast.BasicLit)
	return ok
}

func (fa *funcAnalysis) pos(n ast.Node) string {
	p := fa.fset.Position(n.Pos())
	return fa.rel + ":" + strconv.Itoa(p.Line)
}

func (fa *funcAnalysis) scanSinks() []findings.Finding {
	var out []findings.Finding
	ast.Inspect(fa.fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		// pkg.Fn standard-library sinks.
		if pkgID, ok := sel.X.(*ast.Ident); ok {
			for _, s := range goSinks {
				if pkgID.Name == s.pkg && sel.Sel.Name == s.fn {
					if f, hit := fa.evalSink(call, s); hit {
						fa.hasSink = true
						out = append(out, f)
					}
				}
			}
		}
		// SQL methods on any receiver (db.Query...).
		if _, isSQLMethod := sqlMethods[sel.Sel.Name]; isSQLMethod && len(call.Args) > 0 {
			if f, hit := fa.evalSQL(call); hit {
				fa.hasSink = true
				out = append(out, f)
			}
		}
		return true
	})
	if fa.hasSink {
		if f, hit := fa.evalMissingAuth(); hit {
			out = append(out, f)
		}
	}
	return out
}

// evalSink decides whether a standard-library sink call is a finding and at
// what confidence.
func (fa *funcAnalysis) evalSink(call *ast.CallExpr, s goSink) (findings.Finding, bool) {
	tainted, nonConst := false, false
	check := func(e ast.Expr) {
		if fa.referencesTainted(e) {
			tainted = true
		}
		if !isConstArg(e) {
			nonConst = true
		}
	}
	if s.argIdx == -1 {
		for _, a := range call.Args {
			check(a)
		}
	} else if s.argIdx < len(call.Args) {
		check(call.Args[s.argIdx])
	}

	// Strengthen C1 for an explicit shell invocation (sh/bash -c <nonconst>).
	shellExec := s.class == "C1" && callInvokesShell(call) && nonConst

	switch {
	case tainted || shellExec:
		return fa.mkFinding(call, s, findings.ConfidenceFirm), true
	case nonConst:
		return fa.mkFinding(call, s, findings.ConfidenceTentative), true
	default:
		return findings.Finding{}, false
	}
}

// callInvokesShell reports whether a call looks like exec.Command("sh"|"bash", "-c", ...).
func callInvokesShell(call *ast.CallExpr) bool {
	if len(call.Args) < 2 {
		return false
	}
	first := litValue(call.Args[0])
	if first != "sh" && first != "bash" && first != "/bin/sh" && first != "/bin/bash" && first != "zsh" {
		return false
	}
	return litValue(call.Args[1]) == "-c"
}

func (fa *funcAnalysis) evalSQL(call *ast.CallExpr) (findings.Finding, bool) {
	sel := call.Fun.(*ast.SelectorExpr)
	argIdx := sqlMethods[sel.Sel.Name]
	if argIdx >= len(call.Args) {
		return findings.Finding{}, false
	}
	q := call.Args[argIdx]
	concat := isConcat(q)
	tainted := fa.referencesTainted(q)
	if !concat && !tainted {
		return findings.Finding{}, false
	}
	conf := findings.ConfidenceTentative
	if tainted {
		conf = findings.ConfidenceFirm
	}
	s := goSink{class: "C4", cwe: "CWE-89", title: "SQL query built by string concatenation", severity: findings.SeverityHigh}
	return fa.mkFinding(call, s, conf), true
}

// isConcat reports whether e is a string concatenation with a non-literal part.
func isConcat(e ast.Expr) bool {
	bin, ok := e.(*ast.BinaryExpr)
	if !ok || bin.Op != token.ADD {
		return false
	}
	return !isConstArg(bin.X) || !isConstArg(bin.Y) || isConcat(bin.X) || isConcat(bin.Y)
}

// evalMissingAuth emits a conservative C6 when a handler-like function reaches a
// sink without any visible authorization reference.
func (fa *funcAnalysis) evalMissingAuth() (findings.Finding, bool) {
	name := strings.ToLower(fa.fn.Name.Name)
	handlerish := strings.Contains(name, "handle") || strings.Contains(name, "tool") || strings.HasSuffix(name, "handler")
	if !handlerish {
		return findings.Finding{}, false
	}
	body := strings.ToLower(fa.text(fa.fn))
	for _, kw := range authKeywords {
		if strings.Contains(body, kw) {
			return findings.Finding{}, false
		}
	}
	f := findings.Finding{
		RuleID:     "C6.missing-authz",
		Class:      "C6",
		Title:      "Handler reaches a sensitive operation with no visible authorization check",
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceTentative,
		Modes:      []findings.Mode{findings.ModeWhite},
		Target:     findings.Target{Source: fa.pos(fa.fn), Tool: fa.toolFor(fa.fn)},
		Evidence: findings.Evidence{
			SourceSnippet: fa.text(fa.fn),
			Note:          fmt.Sprintf("func %s() at %s: handler reaches sensitive operations but contains no auth/authz check (looked for: token, auth, permission, rbac, acl, policy, allowed, forbidden)", fa.fn.Name.Name, fa.pos(fa.fn)),
		},
		CWE:         "CWE-862",
		References:  []string{"broken-object-authorization"},
		Remediation: "Confirm the handler enforces per-caller authorization before the sensitive operation; tool handlers must not rely on transport authentication alone.",
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return f, true
}

func (fa *funcAnalysis) mkFinding(call *ast.CallExpr, s goSink, conf findings.Confidence) findings.Finding {
	f := findings.Finding{
		RuleID:     "C.go." + s.class,
		Class:      s.class,
		Title:      s.title,
		Severity:   s.severity,
		Confidence: conf,
		Modes:      []findings.Mode{findings.ModeWhite},
		Target:     findings.Target{Source: fa.pos(call), Tool: fa.toolFor(call)},
		Evidence: findings.Evidence{
			SourceSnippet: fa.text(call),
			Note:          fmt.Sprintf("func %s() at %s: tainted data flows into %s sink %q", fa.fn.Name.Name, fa.pos(call), s.class, s.title),
		},
		CWE:         s.cwe,
		References:  []string{"static-sink"},
		Remediation: remediationFor(s.class),
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return f
}

func remediationFor(class string) string {
	switch class {
	case "C1":
		return "Never pass untrusted input to a shell. Use exec.Command with a fixed argv and validated arguments; avoid sh -c."
	case "C2":
		return "Canonicalize and constrain the path (filepath.Clean + a base-directory check) before reading; reject traversal."
	case "C3":
		return "Validate the URL against an allowlist and block internal/metadata addresses before fetching."
	case "C4":
		return "Use parameterized queries (placeholders) instead of building SQL by concatenation."
	default:
		return ""
	}
}

func litValue(e ast.Expr) string {
	if bl, ok := e.(*ast.BasicLit); ok {
		return strings.Trim(bl.Value, "`\"")
	}
	return ""
}
