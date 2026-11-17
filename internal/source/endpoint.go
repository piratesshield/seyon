package source

import (
	"fmt"
	"strings"
)

// Scheme identifies how to reach a live MCP server.
type Scheme int

const (
	// SchemeStdio spawns a local process and speaks over stdin/stdout.
	SchemeStdio Scheme = iota
	// SchemeHTTP connects to a Streamable HTTP/SSE endpoint.
	SchemeHTTP
)

// EndpointSpec describes a live target parsed from a CLI argument.
//
//	stdio:<command> [args...]   -> a local process
//	http(s)://host/path         -> a Streamable HTTP endpoint
type EndpointSpec struct {
	Scheme  Scheme
	Command string   // for stdio
	Args    []string // for stdio
	URL     string   // for http(s)
	Raw     string
}

// ParseEndpoint parses an endpoint argument. It does not connect or spawn
// anything; it only describes the target.
func ParseEndpoint(arg string) (*EndpointSpec, error) {
	switch {
	case strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://"):
		return &EndpointSpec{Scheme: SchemeHTTP, URL: arg, Raw: arg}, nil
	case strings.HasPrefix(arg, "stdio:"):
		rest := strings.TrimSpace(strings.TrimPrefix(arg, "stdio:"))
		if rest == "" {
			return nil, fmt.Errorf("source: stdio endpoint needs a command")
		}
		fields := strings.Fields(rest)
		return &EndpointSpec{
			Scheme:  SchemeStdio,
			Command: fields[0],
			Args:    fields[1:],
			Raw:     arg,
		}, nil
	default:
		return nil, fmt.Errorf("source: unrecognized endpoint %q (want stdio:<cmd> or http(s)://...)", arg)
	}
}
