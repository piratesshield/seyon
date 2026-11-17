// Package discover finds MCP server configurations across IDE clients
// installed on the host: Claude Desktop, Cursor, VS Code (Copilot), Windsurf,
// Codex, and others. It reads config files only — never launches anything.
package discover

import (
	"os"
	"path/filepath"
	"runtime"
)

// IDEConfig describes one discovered MCP configuration file.
type IDEConfig struct {
	IDE  string // human name: "Claude Desktop", "Cursor", etc.
	Path string // absolute path to the config file
}

// FindAll scans well-known paths for MCP configs on the current host. It
// returns all readable config files it finds, silently skipping paths that
// don't exist.
func FindAll() []IDEConfig {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var out []IDEConfig
	for _, c := range candidates(home) {
		if _, err := os.Stat(c.Path); err == nil {
			out = append(out, c)
		}
	}
	return out
}

func candidates(home string) []IDEConfig {
	switch runtime.GOOS {
	case "darwin":
		return macCandidates(home)
	case "linux":
		return linuxCandidates(home)
	case "windows":
		return windowsCandidates(home)
	default:
		return nil
	}
}

func macCandidates(home string) []IDEConfig {
	appSupport := filepath.Join(home, "Library", "Application Support")
	return []IDEConfig{
		{"Claude Desktop", filepath.Join(appSupport, "Claude", "claude_desktop_config.json")},
		{"Cursor", filepath.Join(appSupport, "Cursor", "User", "globalStorage", "cursor.mcp", "mcp.json")},
		{"Cursor", filepath.Join(home, ".cursor", "mcp.json")},
		{"VS Code (Copilot)", filepath.Join(appSupport, "Code", "User", "settings.json")},
		{"VS Code (Copilot)", filepath.Join(home, ".vscode", "mcp.json")},
		{"Windsurf", filepath.Join(appSupport, "Windsurf", "User", "globalStorage", "codeium.windsurf", "mcp.json")},
		{"Windsurf", filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")},
		{"Codex CLI", filepath.Join(home, ".codex", "mcp.json")},
		{"Claude Code", filepath.Join(home, ".claude", "mcp.json")},
		{"Claude Code (project)", filepath.Join(".claude", "mcp.json")},
		{"Project MCP", filepath.Join(".mcp.json")},
		{"Project MCP", filepath.Join("mcp.json")},
	}
}

func linuxCandidates(home string) []IDEConfig {
	xdgConfig := os.Getenv("XDG_CONFIG_HOME")
	if xdgConfig == "" {
		xdgConfig = filepath.Join(home, ".config")
	}
	return []IDEConfig{
		{"Claude Desktop", filepath.Join(xdgConfig, "Claude", "claude_desktop_config.json")},
		{"Cursor", filepath.Join(xdgConfig, "Cursor", "User", "globalStorage", "cursor.mcp", "mcp.json")},
		{"Cursor", filepath.Join(home, ".cursor", "mcp.json")},
		{"VS Code (Copilot)", filepath.Join(xdgConfig, "Code", "User", "settings.json")},
		{"VS Code (Copilot)", filepath.Join(home, ".vscode", "mcp.json")},
		{"Windsurf", filepath.Join(xdgConfig, "Windsurf", "User", "globalStorage", "codeium.windsurf", "mcp.json")},
		{"Codex CLI", filepath.Join(home, ".codex", "mcp.json")},
		{"Claude Code", filepath.Join(home, ".claude", "mcp.json")},
		{"Claude Code (project)", filepath.Join(".claude", "mcp.json")},
		{"Project MCP", filepath.Join(".mcp.json")},
		{"Project MCP", filepath.Join("mcp.json")},
	}
}

func windowsCandidates(home string) []IDEConfig {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = filepath.Join(home, "AppData", "Roaming")
	}
	return []IDEConfig{
		{"Claude Desktop", filepath.Join(appData, "Claude", "claude_desktop_config.json")},
		{"Cursor", filepath.Join(appData, "Cursor", "User", "globalStorage", "cursor.mcp", "mcp.json")},
		{"Cursor", filepath.Join(home, ".cursor", "mcp.json")},
		{"VS Code (Copilot)", filepath.Join(appData, "Code", "User", "settings.json")},
		{"VS Code (Copilot)", filepath.Join(home, ".vscode", "mcp.json")},
		{"Windsurf", filepath.Join(appData, "Windsurf", "User", "globalStorage", "codeium.windsurf", "mcp.json")},
		{"Codex CLI", filepath.Join(home, ".codex", "mcp.json")},
		{"Claude Code", filepath.Join(home, ".claude", "mcp.json")},
		{"Claude Code (project)", filepath.Join(".claude", "mcp.json")},
		{"Project MCP", filepath.Join(".mcp.json")},
		{"Project MCP", filepath.Join("mcp.json")},
	}
}
