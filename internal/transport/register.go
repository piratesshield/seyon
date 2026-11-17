package transport

import (
	"context"
	"net/http"

	"seyon/internal/mcp"
)

// init wires the concrete transport constructors into the mcp package. This
// avoids an import cycle (mcp needs to create transports; transport needs to
// implement the mcp.Transport interface) by registering function pointers at
// program start.
func init() {
	mcp.NewStreamableHTTP = func(url string, headers http.Header, client *http.Client) mcp.Transport {
		opts := []HTTPOption{}
		if headers != nil {
			opts = append(opts, WithHeaders(headers))
		}
		if client != nil {
			opts = append(opts, WithHTTPClient(client))
		}
		return NewHTTP(url, opts...)
	}
	mcp.NewLegacySSE = func(ctx context.Context, url string, headers http.Header, client *http.Client) (mcp.Transport, error) {
		opts := []LegacySSEOption{}
		if headers != nil {
			opts = append(opts, WithSSEHeaders(headers))
		}
		if client != nil {
			opts = append(opts, WithSSEClient(client))
		}
		t := NewLegacySSE(url, opts...)
		if err := t.Dial(ctx); err != nil {
			return nil, err
		}
		return t, nil
	}
}
