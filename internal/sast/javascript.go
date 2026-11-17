package sast

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/file"
	"github.com/dop251/goja/parser"
	"github.com/dop251/goja/token"

	"seyon/internal/findings"
)

// jsAstPkg gates the reflection walker to goja's ast package, so it can never
// escape into file/token/unistring internals (which could cycle).
var jsAstPkg = reflect.TypeOf(ast.Program{}).PkgPath()

// jsInspect walks the goja AST in pre-order, calling visit on every node;
// returning false from visit skips that node's children (like go/ast.Inspect).
func jsInspect(n ast.Node, visit func(ast.Node) bool) {
	if n == nil {
		return
	}
	rv := reflect.ValueOf(n)
	if (rv.Kind() == reflect.Ptr || rv.Kind() == reflect.Interface) && rv.IsNil() {
		return
	}
	if !visit(n) {
		return
	}
	jsDescend(rv, visit)
}

func jsDescend(v reflect.Value, visit func(ast.Node) bool) {
	switch v.Kind() {
	case reflect.Interface, reflect.Ptr:
		if v.IsNil() {
			return
		}
		jsDescend(v.Elem(), visit)
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			jsChild(v.Index(i), visit)
		}
	case reflect.Struct:
		if v.Type().PkgPath() != jsAstPkg {
			return // do not descend into file.*, token.*, unistring.*
		}
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath != "" {
				continue // unexported
			}
			jsChild(v.Field(i), visit)
		}
	}
}

func jsChild(v reflect.Value, visit func(ast.Node) bool) {
	if v.Kind() == reflect.Interface {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return
		}
		if node, ok := v.Interface().(ast.Node); ok {
			jsInspect(node, visit)
			return
		}
		jsDescend(v.Elem(), visit)
		return
	}
	jsDescend(v, visit)
}

// jsSink describes a dangerous JavaScript call.
type jsSink struct {
	class, cwe, title, kind string
	severity                findings.Severity
}

var (
	jsURLBases   = map[string]bool{"axios": true, "http": true, "https": true}
	jsURLMethods = map[string]bool{"get": true, "post": true, "put": true, "delete": true, "patch": true, "request": true}
	jsFSReadFns  = map[string]bool{"readFile": true, "readFileSync": true, "createReadStream": true, "open": true, "openSync": true}
	jsExecBases  = map[string]bool{
		"child_process": true, "cp": true, "childProcess": true,
		"proc": true, "shell": true, "cmd": true,
	}
	jsSQLBases = map[string]bool{
		"db": true, "database": true, "connection": true, "conn": true,
		"pool": true, "client": true, "knex": true, "sequelize": true,
		"prisma": true, "mysql": true, "pg": true, "sql": true,
		"sqlite": true, "cursor": true, "stmt": true, "statement": true,
		"tx": true, "trx": true, "session": true,
	}
	jsCmdSink     = jsSink{class: "C1", cwe: "CWE-78", title: "JavaScript command executed from untrusted input", kind: "cmd", severity: findings.SeverityHigh}
	jsCodeSink    = jsSink{class: "C1", cwe: "CWE-95", title: "JavaScript eval of untrusted input", kind: "code", severity: findings.SeverityHigh}
	jsURLSink     = jsSink{class: "C3", cwe: "CWE-918", title: "JavaScript HTTP fetch of an untrusted URL (SSRF)", kind: "url", severity: findings.SeverityHigh}
	jsPathSink    = jsSink{class: "C2", cwe: "CWE-22", title: "JavaScript file read from an untrusted path", kind: "path", severity: findings.SeverityMedium}
	jsSQLSinkSpec = jsSink{class: "C4", cwe: "CWE-89", title: "JavaScript SQL query built from untrusted input", kind: "sql", severity: findings.SeverityHigh}
)

// analyzeJS runs intra-function taint analysis over a JavaScript/TypeScript
// source file using goja's parser. It reports C1–C4 findings at firm confidence
// when a parameter-derived value reaches a sink, tentative when a non-literal
// reaches one. The bool is false when the file does not parse (e.g. TypeScript
// type syntax or JSX), so the caller can fall back to the pattern engine.
func analyzeJS(rel string, src []byte) (out []findings.Finding, ok bool) {
	// Defend against any parser/walker panic on malformed input: fall back to
	// the pattern engine rather than crashing the scan.
	defer func() {
		if r := recover(); r != nil {
			out, ok = nil, false
		}
	}()
	prog, err := parser.ParseFile(nil, rel, string(src), 0)
	if err != nil {
		return nil, false
	}
	toolMap := extractJSToolMap(src)
	var funcs []*jsFunc
	for _, st := range prog.Body {
		jsInspect(st, func(n ast.Node) bool {
			switch fn := n.(type) {
			case *ast.FunctionLiteral:
				funcs = append(funcs, &jsFunc{rel: rel, src: src, file: prog.File, params: jsParams(fn.ParameterList), body: fn.Body, toolMap: toolMap})
			case *ast.ArrowFunctionLiteral:
				funcs = append(funcs, &jsFunc{rel: rel, src: src, file: prog.File, params: jsParams(fn.ParameterList), body: fn.Body, toolMap: toolMap})
			}
			return true
		})
	}
	for _, jf := range funcs {
		jf.computeTaint()
		out = append(out, jf.scan()...)
	}
	return out, true
}

type jsFunc struct {
	rel     string
	src     []byte
	file    *file.File
	params  []string
	body    ast.Node
	tainted map[string]bool
	toolMap map[string]string
}

func (jf *jsFunc) snippetAt(line int) string {
	lines := strings.Split(string(jf.src), "\n")
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

func jsParams(pl *ast.ParameterList) []string {
	if pl == nil {
		return nil
	}
	var out []string
	for _, b := range pl.List {
		if id, ok := b.Target.(*ast.Identifier); ok {
			out = append(out, string(id.Name))
		}
	}
	return out
}

// bodyInspect walks the function body, stopping at nested functions (each
// analyzed on its own).
func (jf *jsFunc) bodyInspect(visit func(ast.Node) bool) {
	jsInspect(jf.body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral:
			return false
		}
		return visit(n)
	})
}

func (jf *jsFunc) computeTaint() {
	jf.tainted = map[string]bool{}
	for _, p := range jf.params {
		jf.tainted[p] = true
	}
	for pass := 0; pass < 5; pass++ {
		changed := false
		jf.bodyInspect(func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.Binding:
				if id, ok := s.Target.(*ast.Identifier); ok && s.Initializer != nil {
					if jf.refsTainted(s.Initializer) && !jf.tainted[string(id.Name)] {
						jf.tainted[string(id.Name)] = true
						changed = true
					}
				}
			case *ast.AssignExpression:
				if id, ok := s.Left.(*ast.Identifier); ok {
					if jf.refsTainted(s.Right) && !jf.tainted[string(id.Name)] {
						jf.tainted[string(id.Name)] = true
						changed = true
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

func (jf *jsFunc) scan() []findings.Finding {
	var out []findings.Finding
	jf.bodyInspect(func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpression); ok {
			if f, hit := jf.evalCall(call); hit {
				out = append(out, f)
			}
		}
		return true
	})
	return out
}

func (jf *jsFunc) evalCall(call *ast.CallExpression) (findings.Finding, bool) {
	name := jsDotted(call.Callee)
	if name == "" {
		return findings.Finding{}, false
	}
	base, last := splitLast(name)

	var spec jsSink
	switch {
	case last == "execSync" && !isDotCall(call):
		spec = jsCmdSink
	case last == "execSync" && jsExecBases[base]:
		spec = jsCmdSink
	case last == "exec" && !isDotCall(call):
		spec = jsCmdSink
	case last == "exec" && jsExecBases[base]:
		spec = jsCmdSink
	case name == "eval":
		spec = jsCodeSink
	case name == "fetch" || (jsURLBases[base] && jsURLMethods[last]):
		spec = jsURLSink
	case base == "fs" && jsFSReadFns[last]:
		spec = jsPathSink
	case last == "execute" || last == "executemany":
		spec = jsSQLSinkSpec
	case last == "query" && jsSQLBases[base]:
		spec = jsSQLSinkSpec
	default:
		return findings.Finding{}, false
	}

	if len(call.ArgumentList) == 0 {
		return findings.Finding{}, false
	}
	arg := call.ArgumentList[0]
	requireConcat := spec.kind == "path" || spec.kind == "sql"
	switch {
	case jf.refsTainted(arg):
		return jf.mkFinding(spec, call), true
	case requireConcat && jsIsConcat(arg):
		return jf.mkFindingConf(spec, call, findings.ConfidenceTentative), true
	case !requireConcat && !jsIsConst(arg):
		return jf.mkFindingConf(spec, call, findings.ConfidenceTentative), true
	default:
		return findings.Finding{}, false
	}
}

func (jf *jsFunc) mkFinding(spec jsSink, call *ast.CallExpression) findings.Finding {
	return jf.mkFindingConf(spec, call, findings.ConfidenceFirm)
}

func (jf *jsFunc) mkFindingConf(spec jsSink, call *ast.CallExpression, conf findings.Confidence) findings.Finding {
	line := jf.file.Position(int(call.Idx0())).Line
	toolName := jf.inferTool()
	f := findings.Finding{
		RuleID:     "C.js." + spec.class,
		Class:      spec.class,
		Title:      spec.title,
		Severity:   spec.severity,
		Confidence: conf,
		Modes:      []findings.Mode{findings.ModeWhite},
		Target:     findings.Target{Tool: toolName, Source: jf.rel + ":" + strconv.Itoa(line)},
		Evidence: findings.Evidence{
			Note:          fmt.Sprintf("at %s:%d: tainted data flows into %s sink %q — user-controlled input reaches a dangerous call without sanitization", jf.rel, line, spec.class, spec.title),
			SourceSnippet: jf.snippetAt(line),
		},
		CWE:         spec.cwe,
		References:  []string{"static-dataflow"},
		Remediation: remediationFor(spec.class),
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return f
}

func (jf *jsFunc) inferTool() string {
	if len(jf.toolMap) == 1 {
		for _, v := range jf.toolMap {
			return v
		}
	}
	return ""
}

func (jf *jsFunc) refsTainted(e ast.Expression) bool {
	found := false
	jsInspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Identifier); ok && jf.tainted[string(id.Name)] {
			found = true
			return false
		}
		return true
	})
	return found
}

// jsDotted renders a dotted call target (cp.exec, axios.get, fetch); it returns
// "" for a target it cannot name.
func jsDotted(e ast.Expression) string {
	switch x := e.(type) {
	case *ast.Identifier:
		return string(x.Name)
	case *ast.DotExpression:
		base := jsDotted(x.Left)
		if base == "" {
			return string(x.Identifier.Name)
		}
		return base + "." + string(x.Identifier.Name)
	}
	return ""
}

func isDotCall(call *ast.CallExpression) bool {
	_, ok := call.Callee.(*ast.DotExpression)
	return ok
}

func splitLast(name string) (base, last string) {
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[:i], name[i+1:]
	}
	return "", name
}

func jsIsConst(e ast.Expression) bool {
	switch x := e.(type) {
	case *ast.StringLiteral, *ast.NumberLiteral, *ast.BooleanLiteral, *ast.NullLiteral:
		return true
	case *ast.ArrayLiteral:
		for _, el := range x.Value {
			if !jsIsConst(el) {
				return false
			}
		}
		return true
	}
	return false
}

func jsIsConcat(e ast.Expression) bool {
	switch x := e.(type) {
	case *ast.BinaryExpression:
		if x.Operator == token.PLUS {
			return !jsIsConst(x.Left) || !jsIsConst(x.Right) || jsIsConcat(x.Left) || jsIsConcat(x.Right)
		}
	case *ast.TemplateLiteral:
		return len(x.Expressions) > 0
	}
	return false
}
