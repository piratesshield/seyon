package sast

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-python/gpython/ast"
	"github.com/go-python/gpython/parser"
	"github.com/go-python/gpython/py"

	"seyon/internal/findings"
)

// pySink describes a dangerous Python call and how to judge it.
type pySink struct {
	class, cwe, title, kind string
	severity                findings.Severity
	argIdx                  int
}

// pySinks maps a fully-qualified (or bare) call name to its sink. SQL
// (.execute/.executemany on any receiver) is matched separately by suffix.
var pySinks = map[string]pySink{
	"os.system": {class: "C1", cwe: "CWE-78", title: "Python command executed from untrusted input", kind: "cmd", severity: findings.SeverityCritical, argIdx: 0},
	"os.popen":  {class: "C1", cwe: "CWE-78", title: "Python command executed from untrusted input", kind: "cmd", severity: findings.SeverityCritical, argIdx: 0},
	"eval":      {class: "C1", cwe: "CWE-95", title: "Python eval of untrusted input", kind: "code", severity: findings.SeverityHigh, argIdx: 0},
	"exec":      {class: "C1", cwe: "CWE-95", title: "Python exec of untrusted input", kind: "code", severity: findings.SeverityHigh, argIdx: 0},
	"open":      {class: "C2", cwe: "CWE-22", title: "Python file opened from an untrusted path", kind: "path", severity: findings.SeverityHigh, argIdx: 0},

	"subprocess.run":          {class: "C1", cwe: "CWE-78", title: "Python subprocess from untrusted input", kind: "subprocess", severity: findings.SeverityCritical, argIdx: 0},
	"subprocess.call":         {class: "C1", cwe: "CWE-78", title: "Python subprocess from untrusted input", kind: "subprocess", severity: findings.SeverityCritical, argIdx: 0},
	"subprocess.Popen":        {class: "C1", cwe: "CWE-78", title: "Python subprocess from untrusted input", kind: "subprocess", severity: findings.SeverityCritical, argIdx: 0},
	"subprocess.check_output": {class: "C1", cwe: "CWE-78", title: "Python subprocess from untrusted input", kind: "subprocess", severity: findings.SeverityCritical, argIdx: 0},
	"subprocess.check_call":   {class: "C1", cwe: "CWE-78", title: "Python subprocess from untrusted input", kind: "subprocess", severity: findings.SeverityCritical, argIdx: 0},

	"requests.get":           {class: "C3", cwe: "CWE-918", title: "Python HTTP fetch of an untrusted URL (SSRF)", kind: "url", severity: findings.SeverityHigh, argIdx: 0},
	"requests.post":          {class: "C3", cwe: "CWE-918", title: "Python HTTP fetch of an untrusted URL (SSRF)", kind: "url", severity: findings.SeverityHigh, argIdx: 0},
	"requests.put":           {class: "C3", cwe: "CWE-918", title: "Python HTTP fetch of an untrusted URL (SSRF)", kind: "url", severity: findings.SeverityHigh, argIdx: 0},
	"requests.delete":        {class: "C3", cwe: "CWE-918", title: "Python HTTP fetch of an untrusted URL (SSRF)", kind: "url", severity: findings.SeverityHigh, argIdx: 0},
	"requests.head":          {class: "C3", cwe: "CWE-918", title: "Python HTTP fetch of an untrusted URL (SSRF)", kind: "url", severity: findings.SeverityHigh, argIdx: 0},
	"requests.patch":         {class: "C3", cwe: "CWE-918", title: "Python HTTP fetch of an untrusted URL (SSRF)", kind: "url", severity: findings.SeverityHigh, argIdx: 0},
	"httpx.get":              {class: "C3", cwe: "CWE-918", title: "Python HTTP fetch of an untrusted URL (SSRF)", kind: "url", severity: findings.SeverityHigh, argIdx: 0},
	"httpx.post":             {class: "C3", cwe: "CWE-918", title: "Python HTTP fetch of an untrusted URL (SSRF)", kind: "url", severity: findings.SeverityHigh, argIdx: 0},
	"urllib.request.urlopen": {class: "C3", cwe: "CWE-918", title: "Python HTTP fetch of an untrusted URL (SSRF)", kind: "url", severity: findings.SeverityHigh, argIdx: 0},
}

// analyzePython runs intra-function taint analysis over a Python source file
// using gpython's AST. It reports C1–C4 findings at firm confidence when a
// parameter-derived value reaches a sink, tentative when a non-literal reaches
// one. The bool is false when the file does not parse, so the caller can fall
// back to the pattern engine.
func analyzePython(rel string, src []byte) (out []findings.Finding, ok bool) {
	// gpython's parser can panic on some malformed inputs; a scan of an
	// untrusted tree must degrade to the pattern fallback, never crash.
	defer func() {
		if r := recover(); r != nil {
			out, ok = nil, false
		}
	}()
	mod, err := parser.ParseString(string(src), py.ExecMode)
	if err != nil {
		return nil, false
	}
	var funcs []*ast.FunctionDef
	ast.Walk(mod, func(n ast.Ast) bool {
		if fd, ok := n.(*ast.FunctionDef); ok {
			funcs = append(funcs, fd)
		}
		return true
	})
	toolMap := extractPyToolMap(src)
	for _, fd := range funcs {
		pa := &pyFunc{rel: rel, src: src, fn: fd, toolMap: toolMap}
		pa.computeTaint()
		out = append(out, pa.scan()...)
	}
	return out, true
}

type pyFunc struct {
	rel     string
	src     []byte
	fn      *ast.FunctionDef
	tainted map[string]bool
	toolMap map[string]string
}

func (pa *pyFunc) snippetAt(line int) string {
	lines := strings.Split(string(pa.src), "\n")
	start := line - 2
	if start < 0 {
		start = 0
	}
	end := line + 1
	if end > len(lines) {
		end = len(lines)
	}
	var out []string
	for i := start; i < end; i++ {
		marker := "  "
		if i == line-1 {
			marker = "> "
		}
		out = append(out, fmt.Sprintf("%s%4d | %s", marker, i+1, lines[i]))
	}
	return strings.Join(out, "\n")
}

// bodyWalk walks the statements of the function, skipping nested function and
// lambda definitions (each analyzed on its own), invoking fn for every node.
func (pa *pyFunc) bodyWalk(fn func(ast.Ast)) {
	for _, stmt := range pa.fn.Body {
		ast.Walk(stmt, func(n ast.Ast) bool {
			switch n.(type) {
			case *ast.FunctionDef, *ast.Lambda:
				return false
			}
			fn(n)
			return true
		})
	}
}

func (pa *pyFunc) computeTaint() {
	pa.tainted = map[string]bool{}
	seedArgs(pa.fn.Args, pa.tainted)
	for pass := 0; pass < 5; pass++ {
		changed := false
		pa.bodyWalk(func(n ast.Ast) {
			switch s := n.(type) {
			case *ast.Assign:
				if pa.refsTainted(s.Value) {
					for _, t := range s.Targets {
						if name, ok := t.(*ast.Name); ok && !pa.tainted[string(name.Id)] {
							pa.tainted[string(name.Id)] = true
							changed = true
						}
					}
				}
			case *ast.AugAssign:
				if pa.refsTainted(s.Value) {
					if name, ok := s.Target.(*ast.Name); ok && !pa.tainted[string(name.Id)] {
						pa.tainted[string(name.Id)] = true
						changed = true
					}
				}
			}
		})
		if !changed {
			break
		}
	}
}

func seedArgs(args *ast.Arguments, set map[string]bool) {
	if args == nil {
		return
	}
	add := func(a *ast.Arg) {
		if a != nil && string(a.Arg) != "" {
			set[string(a.Arg)] = true
		}
	}
	for _, a := range args.Args {
		add(a)
	}
	for _, a := range args.Kwonlyargs {
		add(a)
	}
	add(args.Vararg)
	add(args.Kwarg)
}

// scan walks the body tracking the nearest statement line and evaluates each
// call against the sink table.
func (pa *pyFunc) scan() []findings.Finding {
	var out []findings.Finding
	line := pa.fn.GetLineno()
	pa.bodyWalk(func(n ast.Ast) {
		if s, ok := n.(ast.Stmt); ok {
			if l := s.GetLineno(); l > 0 {
				line = l
			}
		}
		if call, ok := n.(*ast.Call); ok {
			if f, hit := pa.evalCall(call, line); hit {
				out = append(out, f)
			}
		}
	})
	return out
}

func (pa *pyFunc) evalCall(call *ast.Call, line int) (findings.Finding, bool) {
	name := pyDotted(call.Func)
	if name == "" {
		return findings.Finding{}, false
	}
	if strings.HasSuffix(name, ".execute") || strings.HasSuffix(name, ".executemany") {
		return pa.flowFinding(call, pySink{class: "C4", cwe: "CWE-89", title: "Python SQL query built from untrusted input", kind: "sql", severity: findings.SeverityHigh, argIdx: 0}, line, true)
	}
	spec, ok := pySinks[name]
	if !ok {
		return findings.Finding{}, false
	}
	if spec.kind == "subprocess" {
		return pa.subprocessFinding(call, spec, line)
	}
	// path/sql require a concatenation or taint; cmd/url/code accept any
	// non-literal.
	return pa.flowFinding(call, spec, line, spec.kind == "path")
}

// flowFinding evaluates a positional-argument sink. When requireConcat is set
// (path/sql), a plain non-literal is not enough — only a concatenation or a
// tainted value is reported.
func (pa *pyFunc) flowFinding(call *ast.Call, spec pySink, line int, requireConcat bool) (findings.Finding, bool) {
	if spec.argIdx >= len(call.Args) {
		return findings.Finding{}, false
	}
	arg := call.Args[spec.argIdx]
	tainted := pa.refsTainted(arg)
	switch {
	case tainted:
		return pa.mkFinding(spec, line, findings.ConfidenceFirm), true
	case requireConcat && pyIsConcat(arg):
		return pa.mkFinding(spec, line, findings.ConfidenceTentative), true
	case !requireConcat && !pyIsConst(arg):
		return pa.mkFinding(spec, line, findings.ConfidenceTentative), true
	default:
		return findings.Finding{}, false
	}
}

func (pa *pyFunc) subprocessFinding(call *ast.Call, spec pySink, line int) (findings.Finding, bool) {
	shellTrue := false
	for _, kw := range call.Keywords {
		if string(kw.Arg) == "shell" {
			if nc, ok := kw.Value.(*ast.NameConstant); ok && nc.Value == py.True {
				shellTrue = true
			}
		}
	}
	var arg ast.Expr
	if spec.argIdx < len(call.Args) {
		arg = call.Args[spec.argIdx]
	}
	tainted := arg != nil && pa.refsTainted(arg)
	nonconst := arg != nil && !pyIsConst(arg)
	switch {
	case tainted:
		return pa.mkFinding(spec, line, findings.ConfidenceFirm), true
	case shellTrue && nonconst:
		return pa.mkFinding(spec, line, findings.ConfidenceFirm), true
	default:
		return findings.Finding{}, false
	}
}

func (pa *pyFunc) mkFinding(spec pySink, line int, conf findings.Confidence) findings.Finding {
	toolName := ""
	if pa.toolMap != nil {
		toolName = pa.toolMap[string(pa.fn.Name)]
	}
	f := findings.Finding{
		RuleID:     "C.py." + spec.class,
		Class:      spec.class,
		Title:      spec.title,
		Severity:   spec.severity,
		Confidence: conf,
		Modes:      []findings.Mode{findings.ModeWhite},
		Target:     findings.Target{Tool: toolName, Source: pa.rel + ":" + strconv.Itoa(line)},
		Evidence: findings.Evidence{
			Note:          fmt.Sprintf("def %s() at %s:%d: tainted data flows into %s sink %q — user-controlled input reaches a dangerous call without sanitization", string(pa.fn.Name), pa.rel, line, spec.class, spec.title),
			SourceSnippet: pa.snippetAt(line),
		},
		CWE:         spec.cwe,
		References:  []string{"static-dataflow"},
		Remediation: remediationFor(spec.class),
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return f
}

func (pa *pyFunc) refsTainted(e ast.Expr) bool {
	found := false
	ast.Walk(e, func(n ast.Ast) bool {
		if name, ok := n.(*ast.Name); ok && pa.tainted[string(name.Id)] {
			found = true
			return false
		}
		return true
	})
	return found
}

// pyDotted renders a dotted call target (os.system, requests.get, eval,
// cursor.execute); it returns "" for anything it cannot name.
func pyDotted(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Name:
		return string(x.Id)
	case *ast.Attribute:
		base := pyDotted(x.Value)
		if base == "" {
			return string(x.Attr)
		}
		return base + "." + string(x.Attr)
	}
	return ""
}

// pyIsConst reports whether e is a literal (or a collection of literals), so a
// fixed argv or URL is not treated as untrusted.
func pyIsConst(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Str, *ast.Num, *ast.Bytes, *ast.NameConstant:
		return true
	case *ast.List:
		return allConst(x.Elts)
	case *ast.Tuple:
		return allConst(x.Elts)
	}
	return false
}

func allConst(es []ast.Expr) bool {
	for _, e := range es {
		if !pyIsConst(e) {
			return false
		}
	}
	return true
}

// pyIsConcat reports whether e builds a string by + concatenation (or %-format)
// with a non-literal part.
func pyIsConcat(e ast.Expr) bool {
	bin, ok := e.(*ast.BinOp)
	if !ok {
		return false
	}
	// A "+" or "%" with any non-literal operand looks like a built string.
	return !pyIsConst(bin.Left) || !pyIsConst(bin.Right) || pyIsConcat(bin.Left) || pyIsConcat(bin.Right)
}
