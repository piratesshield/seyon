// Package surface is the normalized tool/resource/prompt surface of an MCP
// server, as the gray-box detectors see it. It is produced either from a live
// enumeration (an mcp.Inventory) or from a captured tools/list snapshot file.
package surface

import (
	"encoding/json"
	"fmt"

	"seyon/internal/mcp"
)

// Surface is the declared capability surface of a server.
type Surface struct {
	Server    string         `json:"server,omitempty"`
	Tools     []mcp.Tool     `json:"tools"`
	Resources []mcp.Resource `json:"resources"`
	Prompts   []mcp.Prompt   `json:"prompts"`
	// Origin records where the surface came from, for reporting.
	Origin string `json:"origin,omitempty"`
}

// FromInventory builds a surface from a live enumeration.
func FromInventory(inv *mcp.Inventory, origin string) *Surface {
	return &Surface{
		Server:    inv.Server.Name,
		Tools:     inv.Tools,
		Resources: inv.Resources,
		Prompts:   inv.Prompts,
		Origin:    origin,
	}
}

// snapshot matches a captured tools/list-style JSON file. Each list is
// optional, so a file holding only tools is valid.
type snapshot struct {
	Server    string         `json:"server"`
	Tools     []mcp.Tool     `json:"tools"`
	Resources []mcp.Resource `json:"resources"`
	Prompts   []mcp.Prompt   `json:"prompts"`
}

// Looks reports whether b plausibly is a surface snapshot (has a tools,
// resources, or prompts array).
func Looks(b []byte) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return false
	}
	_, hasTools := probe["tools"]
	_, hasRes := probe["resources"]
	_, hasPrompts := probe["prompts"]
	return hasTools || hasRes || hasPrompts
}

// Parse reads a surface snapshot from JSON bytes.
func Parse(b []byte, origin string) (*Surface, error) {
	var s snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("surface: parse snapshot: %w", err)
	}
	return &Surface{
		Server:    s.Server,
		Tools:     s.Tools,
		Resources: s.Resources,
		Prompts:   s.Prompts,
		Origin:    origin,
	}, nil
}
