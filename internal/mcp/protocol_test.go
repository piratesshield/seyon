package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestIsUnsupportedProtocol(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"invalid params with protocol version text", &RPCError{Code: -32602, Message: "Unsupported protocol version"}, true},
		{"invalid request with text", &RPCError{Code: -32600, Message: "unsupported protocol"}, true},
		{"other rpc error", &RPCError{Code: -32601, Message: "method not found"}, false},
		{"data list of versions", &RPCError{Code: -32602, Message: "bad", Data: json.RawMessage(`["2025-06-18","2024-11-05"]`)}, true},
		{"data object with versions", &RPCError{Code: -32602, Message: "bad", Data: json.RawMessage(`{"supportedVersions":["2024-11-05"]}`)}, true},
		{"non-rpc error", errors.New("boom"), false},
	}
	for _, c := range cases {
		if got := IsUnsupportedProtocol(c.err); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestSupportedVersionsFromError(t *testing.T) {
	err := &RPCError{Code: -32602, Data: json.RawMessage(`{"supported_versions":["2024-11-05","2025-03-26"]}`)}
	got := SupportedVersionsFromError(err)
	if len(got) != 2 || got[0] != "2024-11-05" || got[1] != "2025-03-26" {
		t.Errorf("unexpected list: %v", got)
	}
	if got := SupportedVersionsFromError(errors.New("plain")); got != nil {
		t.Errorf("non-rpc should return nil, got %v", got)
	}
	// Bad entries are filtered out.
	bad := &RPCError{Code: -32602, Data: json.RawMessage(`["bad","2025-03-26","also-bad"]`)}
	got = SupportedVersionsFromError(bad)
	if len(got) != 1 || got[0] != "2025-03-26" {
		t.Errorf("filterVersions didn't drop junk: %v", got)
	}
}

func TestInitializeNegotiatesVersion(t *testing.T) {
	var attempted []string
	ft := &fakeTransport{}
	ft.handler = func(method string, params json.RawMessage) (interface{}, *RPCError) {
		if method != "initialize" {
			return nil, &RPCError{Code: -32601, Message: "method not found"}
		}
		var p initializeParams
		_ = json.Unmarshal(params, &p)
		attempted = append(attempted, p.ProtocolVersion)
		// Only accept the oldest version.
		if p.ProtocolVersion == "2024-11-05" {
			return map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]interface{}{},
				"serverInfo":      map[string]string{"name": "legacy", "version": "0.1"},
			}, nil
		}
		return nil, &RPCError{Code: -32602, Message: "Unsupported protocol version"}
	}

	c := NewClient(ft)
	res, err := c.Initialize(context.Background())
	if err != nil {
		t.Fatalf("expected successful negotiation, got %v", err)
	}
	if res.ProtocolVersion != "2024-11-05" {
		t.Errorf("expected server version 2024-11-05, got %q", res.ProtocolVersion)
	}
	if len(attempted) < 2 {
		t.Errorf("expected multiple attempts, got %v", attempted)
	}
	if attempted[0] != ProtocolVersion {
		t.Errorf("first attempt should be preferred version %q, got %q", ProtocolVersion, attempted[0])
	}
}

func TestInitializeReordersFromServerHint(t *testing.T) {
	var attempted []string
	ft := &fakeTransport{}
	ft.handler = func(method string, params json.RawMessage) (interface{}, *RPCError) {
		if method != "initialize" {
			return nil, &RPCError{Code: -32601}
		}
		var p initializeParams
		_ = json.Unmarshal(params, &p)
		attempted = append(attempted, p.ProtocolVersion)
		if p.ProtocolVersion == "2024-11-05" {
			return map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]interface{}{},
				"serverInfo":      map[string]string{"name": "hinting-server", "version": "1"},
			}, nil
		}
		return nil, &RPCError{
			Code:    -32602,
			Message: "protocol version not supported",
			Data:    json.RawMessage(`{"supportedVersions":["2024-11-05"]}`),
		}
	}
	c := NewClient(ft)
	if _, err := c.Initialize(context.Background()); err != nil {
		t.Fatalf("negotiation with hint should succeed: %v", err)
	}
	// After the first failure the server hinted 2024-11-05 — the next attempt
	// should be exactly that version, not the next in the static priority list.
	if len(attempted) != 2 {
		t.Fatalf("expected exactly 2 attempts (preferred + hinted), got %v", attempted)
	}
	if attempted[1] != "2024-11-05" {
		t.Errorf("second attempt should respect server hint, got %q", attempted[1])
	}
}

func TestInitializeUsesModernDiscoverWhenSupported(t *testing.T) {
	var methods []string
	ft := &fakeTransport{}
	ft.handler = func(method string, params json.RawMessage) (interface{}, *RPCError) {
		methods = append(methods, method)
		switch method {
		case "server/discover":
			return map[string]interface{}{
				"protocolVersion":   "2026-07-28",
				"supportedVersions": []string{"2026-07-28", "2025-06-18"},
				"capabilities":      map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":        map[string]string{"name": "modern-server", "version": "2"},
				"instructions":      "be careful",
			}, nil
		}
		return nil, &RPCError{Code: -32601, Message: "method not found"}
	}
	c := NewClient(ft)
	res, err := c.Initialize(context.Background())
	if err != nil {
		t.Fatalf("expected modern discover to succeed: %v", err)
	}
	if res.ProtocolVersion != "2026-07-28" {
		t.Errorf("want protocol 2026-07-28, got %q", res.ProtocolVersion)
	}
	if res.Instructions != "be careful" {
		t.Errorf("instructions not propagated: %q", res.Instructions)
	}
	if len(methods) != 1 || methods[0] != "server/discover" {
		t.Errorf("expected single server/discover call, got %v", methods)
	}
}

func TestInitializeFallsBackFromDiscoverOnMethodNotFound(t *testing.T) {
	var methods []string
	ft := &fakeTransport{}
	ft.handler = func(method string, params json.RawMessage) (interface{}, *RPCError) {
		methods = append(methods, method)
		switch method {
		case "server/discover":
			return nil, &RPCError{Code: -32601, Message: "method not found"}
		case "initialize":
			return map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]interface{}{},
				"serverInfo":      map[string]string{"name": "legacy", "version": "1"},
			}, nil
		}
		return nil, &RPCError{Code: -32601}
	}
	c := NewClient(ft)
	if _, err := c.Initialize(context.Background()); err != nil {
		t.Fatalf("expected fallback to succeed: %v", err)
	}
	if len(methods) < 2 || methods[0] != "server/discover" || methods[1] != "initialize" {
		t.Errorf("expected discover then initialize, got %v", methods)
	}
}

func TestInitializeFailsWithNoCommonVersion(t *testing.T) {
	ft := &fakeTransport{}
	ft.handler = func(_ string, _ json.RawMessage) (interface{}, *RPCError) {
		return nil, &RPCError{Code: -32602, Message: "Unsupported protocol version"}
	}
	c := NewClient(ft)
	_, err := c.Initialize(context.Background())
	if err == nil {
		t.Fatalf("expected negotiation to fail")
	}
	var ne *negotiationError
	if !errors.As(err, &ne) {
		t.Fatalf("expected negotiationError, got %T: %v", err, err)
	}
	if len(ne.Tried) != len(SupportedProtocolVersions) {
		t.Errorf("expected every version to be tried, got %d/%d", len(ne.Tried), len(SupportedProtocolVersions))
	}
}
