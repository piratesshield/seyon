// Package manifest parses MCP client configuration (mcp.json / mcpServers
// blocks) into a normalized model the gray-box detectors inspect. It reads and
// parses only; it never launches a server.
package manifest

import (
	"encoding/json"
	"fmt"
	"sort"
)

// ServerSpec is one configured MCP server. A stdio server sets Command/Args;
// a remote server sets URL. Type is the declared transport when present.
type ServerSpec struct {
	Name    string            `json:"-"`
	Type    string            `json:"type,omitempty"`
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	URL     string            `json:"url,omitempty"`
}

// IsRemote reports whether the server is reached over a URL rather than spawned.
func (s ServerSpec) IsRemote() bool { return s.URL != "" }

// Config is a parsed client configuration.
type Config struct {
	Servers []ServerSpec
}

// rawConfig matches the on-disk shape. Both "mcpServers" (client configs) and
// "servers" (some tools) are accepted.
type rawConfig struct {
	MCPServers map[string]json.RawMessage `json:"mcpServers"`
	Servers    map[string]json.RawMessage `json:"servers"`
}

// Looks reports whether b plausibly is an MCP client configuration.
func Looks(b []byte) bool {
	var r rawConfig
	if err := json.Unmarshal(b, &r); err != nil {
		return false
	}
	return len(r.MCPServers) > 0 || len(r.Servers) > 0
}

// Parse reads a client configuration from JSON bytes. Server entries are
// returned sorted by name for deterministic output.
func Parse(b []byte) (*Config, error) {
	var r rawConfig
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("manifest: parse: %w", err)
	}
	entries := r.MCPServers
	if len(entries) == 0 {
		entries = r.Servers
	}
	cfg := &Config{}
	for name, raw := range entries {
		var s ServerSpec
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("manifest: server %q: %w", name, err)
		}
		s.Name = name
		cfg.Servers = append(cfg.Servers, s)
	}
	sort.Slice(cfg.Servers, func(i, j int) bool { return cfg.Servers[i].Name < cfg.Servers[j].Name })
	return cfg, nil
}
