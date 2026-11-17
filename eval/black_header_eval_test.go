package eval_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"seyon/internal/engine"
	"seyon/internal/source"
)

// authMCPServer is a minimal MCP-over-HTTP server that requires a bearer token.
// Without the right Authorization header it answers every request 401; with it,
// it handles initialize and tools/list (one tool).
func authMCPServer(t *testing.T, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_token","error_description":"Authentication required"}`))
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if len(req.ID) == 0 { // notification (e.g. notifications/initialized)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var result interface{}
		switch req.Method {
		case "initialize":
			result = map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":      map[string]string{"name": "auth-srv", "version": "1.0.0"},
			}
		case "tools/list":
			result = map[string]interface{}{"tools": []map[string]interface{}{
				{"name": "ping", "description": "Ping the service."},
			}}
		default:
			result = map[string]interface{}{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req.ID, "result": result,
		})
	}))
}

func TestBlackHeaderUnlocksEnumeration(t *testing.T) {
	srv := authMCPServer(t, "testtoken")
	defer srv.Close()

	spec, err := source.ParseEndpoint(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Without the token: 401 → auth-required recon finding, no enumeration.
	noauth, err := engine.BlackScan(ctx, "test", spec, engine.BlackOptions{})
	if err != nil {
		t.Fatalf("scan without auth: %v", err)
	}
	if countClass(noauth.Findings, "A") == 0 {
		t.Error("expected an A recon finding without auth")
	}
	foundAuthReq := false
	for _, f := range noauth.Findings {
		if f.RuleID == "A.endpoint.auth-required" {
			foundAuthReq = true
		}
	}
	if !foundAuthReq {
		t.Error("expected A.endpoint.auth-required without a token")
	}

	// With the token: enumeration succeeds, one tool, no auth-required finding.
	withauth, err := engine.BlackScan(ctx, "test", spec, engine.BlackOptions{
		Headers: http.Header{"Authorization": []string{"Bearer testtoken"}},
	})
	if err != nil {
		t.Fatalf("scan with auth: %v", err)
	}
	if withauth.Inventory == nil || withauth.Inventory.Tools != 1 {
		t.Fatalf("expected 1 enumerated tool with auth, got %+v", withauth.Inventory)
	}
	for _, f := range withauth.Findings {
		if f.RuleID == "A.endpoint.auth-required" {
			t.Error("auth-required finding should be gone once authenticated")
		}
	}
}
