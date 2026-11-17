package sast

import (
	"regexp"
	"strings"
)

// Non-Go tool registration recognition for Python and JavaScript/TypeScript.
// These patterns match the common MCP SDK registration idioms so white-box
// findings in those languages can be tool-anchored and correlate cross-mode.

// pyToolPattern matches Python decorator-based tool registration:
//
//	@mcp.tool()            → next def's name is both tool and handler
//	@server.tool()         → same
//	@app.tool("name")      → explicit tool name
//	@mcp.tool(name="name") → keyword form
var pyToolPattern = regexp.MustCompile(
	`@\w+\.tool\(\s*(?:name\s*=\s*)?(?:"([^"]+)"|'([^']+)')?\s*\)`,
)

// pyDefPattern matches a Python function definition immediately after a decorator.
var pyDefPattern = regexp.MustCompile(`(?m)^def\s+(\w+)\s*\(`)

// jsToolPattern matches JS/TS tool registration:
//
//	server.tool("name", ...)
//	app.tool("name", ...)
//	mcp.tool("name", ...)
var jsToolPattern = regexp.MustCompile(
	`\.\s*tool\s*\(\s*"([^"]+)"`)

// extractPyToolMap scans Python source for @xxx.tool() decorators and returns
// a map from handler function name to MCP tool name.
func extractPyToolMap(src []byte) map[string]string {
	lines := strings.Split(string(src), "\n")
	m := map[string]string{}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, ".tool(") || !strings.HasPrefix(trimmed, "@") {
			continue
		}
		matches := pyToolPattern.FindStringSubmatch(trimmed)
		if matches == nil {
			continue
		}
		toolName := matches[1]
		if toolName == "" {
			toolName = matches[2]
		}
		for j := i + 1; j < len(lines) && j <= i+3; j++ {
			defMatch := pyDefPattern.FindStringSubmatch(lines[j])
			if defMatch != nil {
				funcName := defMatch[1]
				if toolName == "" {
					toolName = funcName
				}
				m[funcName] = toolName
				break
			}
		}
	}
	return m
}

// extractJSToolMap scans JS/TS source for .tool("name", ...) calls and returns
// a map from handler name (or the tool name itself as key) to MCP tool name.
// For inline handlers we key by tool name since JS rarely uses named functions.
func extractJSToolMap(src []byte) map[string]string {
	m := map[string]string{}
	lines := strings.Split(string(src), "\n")
	for _, line := range lines {
		if !strings.Contains(line, ".tool(") {
			continue
		}
		matches := jsToolPattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		toolName := matches[1]
		if toolName != "" {
			m[toolName] = toolName
		}
	}
	return m
}
