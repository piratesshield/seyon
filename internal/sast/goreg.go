package sast

import (
	"go/ast"
	"go/token"
	"strconv"
)

// regFuncNames are the call names that register an MCP tool with a handler,
// across the common Go MCP libraries (mark3labs/mcp-go, the official go-sdk,
// and typical hand-rolled servers).
var regFuncNames = map[string]bool{
	"AddTool":        true,
	"RegisterTool":   true,
	"AddToolHandler": true,
	"SetToolHandler": true,
	"HandleTool":     true,
}

// toolConstructors are call names that build a tool spec whose first string
// argument is the tool's name, e.g. mcp.NewTool("name", ...).
var toolConstructors = map[string]bool{
	"NewTool":              true,
	"NewToolWithRawSchema": true,
	"Tool":                 true,
}

// litReg is an inline-closure handler registered for a tool. Sinks whose
// position falls inside the closure body anchor to that tool.
type litReg struct {
	lit  *ast.FuncLit
	tool string
}

// toolRegistry maps handler functions to the MCP tool they implement, so a
// white-box finding inside a handler can be anchored to its tool (and then
// correlated with gray/black findings on the same tool).
type toolRegistry struct {
	byFunc map[string]string   // handler function name -> tool name (whole tree)
	lits   map[string][]litReg // file (rel) -> inline-closure registrations
}

func newToolRegistry() *toolRegistry {
	return &toolRegistry{byFunc: map[string]string{}, lits: map[string][]litReg{}}
}

// collect scans one parsed file for tool registrations and records the
// handler→tool associations it finds.
func (tr *toolRegistry) collect(rel string, file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !regFuncNames[callName(call.Fun)] {
			return true
		}
		tool := firstToolName(call.Args)
		if tool == "" {
			return true
		}
		switch fn, lit := lastHandler(call.Args); {
		case fn != "":
			tr.byFunc[fn] = tool
		case lit != nil:
			tr.lits[rel] = append(tr.lits[rel], litReg{lit: lit, tool: tool})
		}
		return true
	})
}

// toolForFunc returns the tool a named function implements, if any.
func (tr *toolRegistry) toolForFunc(name string) string { return tr.byFunc[name] }

// toolForNode returns the tool whose inline-closure handler (in file rel)
// encloses node n, if any.
func (tr *toolRegistry) toolForNode(rel string, n ast.Node) string {
	for _, lr := range tr.lits[rel] {
		if lr.lit.Pos() <= n.Pos() && n.End() <= lr.lit.End() {
			return lr.tool
		}
	}
	return ""
}

// callName returns the called function's bare name for an Ident (f) or a
// SelectorExpr (x.f).
func callName(fun ast.Expr) string {
	switch x := fun.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}

// firstToolName scans a registration call's arguments for the first tool name
// it can recover, from a bare string, a constructor call, or a Tool struct
// literal's Name field.
func firstToolName(args []ast.Expr) string {
	for _, a := range args {
		if n := toolNameFromExpr(a); n != "" {
			return n
		}
	}
	return ""
}

func toolNameFromExpr(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.BasicLit:
		return stringLit(x)
	case *ast.CallExpr:
		if toolConstructors[callName(x.Fun)] {
			for _, a := range x.Args {
				if s := stringLit(a); s != "" {
					return s
				}
			}
		}
	case *ast.UnaryExpr: // &Tool{...}
		return toolNameFromExpr(x.X)
	case *ast.CompositeLit:
		for _, el := range x.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Name" {
				if s := stringLit(kv.Value); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

// lastHandler returns the handler the registration call attaches: a named
// function (f or x.f) by name, or an inline function literal.
func lastHandler(args []ast.Expr) (string, *ast.FuncLit) {
	if len(args) == 0 {
		return "", nil
	}
	switch h := args[len(args)-1].(type) {
	case *ast.Ident:
		return h.Name, nil
	case *ast.SelectorExpr:
		return h.Sel.Name, nil
	case *ast.FuncLit:
		return "", h
	}
	return "", nil
}

func stringLit(e ast.Expr) string {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return ""
	}
	return s
}
