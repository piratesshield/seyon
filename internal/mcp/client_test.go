package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// fakeTransport answers calls from a handler, exercising the client without a
// real process or socket.
type fakeTransport struct {
	handler func(method string, params json.RawMessage) (interface{}, *RPCError)
	notes   []string
}

func (f *fakeTransport) Call(_ context.Context, req Request) (*Response, error) {
	var params json.RawMessage
	if req.Params != nil {
		b, _ := json.Marshal(req.Params)
		params = b
	}
	result, rpcErr := f.handler(req.Method, params)
	resp := &Response{JSONRPC: "2.0", ID: req.ID}
	if rpcErr != nil {
		resp.Error = rpcErr
		return resp, nil
	}
	b, _ := json.Marshal(result)
	resp.Result = b
	return resp, nil
}

func (f *fakeTransport) Notify(_ context.Context, req Request) error {
	f.notes = append(f.notes, req.Method)
	return nil
}

func (f *fakeTransport) Close() error { return nil }

func TestEnumeratePaginationAndCapabilities(t *testing.T) {
	ft := &fakeTransport{}
	ft.handler = func(method string, params json.RawMessage) (interface{}, *RPCError) {
		switch method {
		case "initialize":
			return map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]interface{}{},
				"serverInfo":      map[string]string{"name": "fake", "version": "1"},
			}, nil
		case "tools/list":
			var p listParams
			_ = json.Unmarshal(params, &p)
			if p.Cursor == "" {
				return map[string]interface{}{
					"tools":      []Tool{{Name: "a"}, {Name: "b"}},
					"nextCursor": "2",
				}, nil
			}
			return map[string]interface{}{"tools": []Tool{{Name: "c"}}}, nil
		case "resources/list":
			return map[string]interface{}{"resources": []Resource{{URI: "file:///x"}}}, nil
		case "prompts/list":
			// Simulate a server that does not implement prompts.
			return nil, &RPCError{Code: -32601, Message: "method not found"}
		default:
			return nil, &RPCError{Code: -32601, Message: "method not found"}
		}
	}

	c := NewClient(ft)
	inv, err := c.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(inv.Tools) != 3 {
		t.Errorf("expected 3 tools across pages, got %d", len(inv.Tools))
	}
	if inv.Tools[2].Name != "c" {
		t.Errorf("pagination order wrong: %+v", inv.Tools)
	}
	if len(inv.Resources) != 1 {
		t.Errorf("expected 1 resource, got %d", len(inv.Resources))
	}
	if len(inv.Prompts) != 0 {
		t.Errorf("expected 0 prompts (method not found), got %d", len(inv.Prompts))
	}
	if !inv.Complete {
		t.Error("inventory should be complete: method-not-found for prompts is not incompleteness")
	}
	// The initialized notification must have been sent.
	found := false
	for _, n := range ft.notes {
		if n == "notifications/initialized" {
			found = true
		}
	}
	if !found {
		t.Error("client did not send notifications/initialized")
	}
}

func TestIsMethodNotFoundWrapped(t *testing.T) {
	rpc := &RPCError{Code: -32601, Message: "method not found"}
	if !isMethodNotFound(rpc) {
		t.Error("direct *RPCError not recognized")
	}
	if !isMethodNotFound(fmt.Errorf("enumerate prompts: %w", rpc)) {
		t.Error("wrapped *RPCError not recognized")
	}
	if isMethodNotFound(fmt.Errorf("some other error")) {
		t.Error("non-RPC error misclassified as method-not-found")
	}
	if isMethodNotFound(&RPCError{Code: -32000}) {
		t.Error("different RPC code misclassified")
	}
}

func TestCallSurfacesRPCError(t *testing.T) {
	ft := &fakeTransport{handler: func(method string, _ json.RawMessage) (interface{}, *RPCError) {
		if method == "initialize" {
			return nil, &RPCError{Code: -32000, Message: "boom"}
		}
		return nil, nil
	}}
	c := NewClient(ft)
	_, err := c.Initialize(context.Background())
	if err == nil {
		t.Fatal("expected error from initialize")
	}
	if _, ok := err.(*RPCError); !ok {
		t.Errorf("expected *RPCError, got %T", err)
	}
}
