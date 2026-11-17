package mcp

import "context"

// Transport carries JSON-RPC messages to and from an MCP server. Implementations
// exist for stdio (a spawned local process) and Streamable HTTP/SSE.
type Transport interface {
	// Call sends a request and returns the response whose id matches.
	Call(ctx context.Context, req Request) (*Response, error)
	// Notify sends a notification, which expects no response.
	Notify(ctx context.Context, req Request) error
	// Close releases the transport's resources.
	Close() error
}
