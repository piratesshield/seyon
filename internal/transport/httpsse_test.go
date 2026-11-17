package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"seyon/internal/mcp"
)

func newReq(t *testing.T, id int, method string) mcp.Request {
	t.Helper()
	raw, _ := json.Marshal(id)
	return mcp.Request{JSONRPC: "2.0", ID: raw, Method: method}
}

func TestHTTPJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("MCP-Protocol-Version"); got != mcp.ProtocolVersion {
			t.Errorf("missing/wrong protocol header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "sess-1")
		var req mcp.Request
		_ = json.NewDecoder(r.Body).Decode(&req)
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}`, string(req.ID))
	}))
	defer srv.Close()

	h := NewHTTP(srv.URL)
	resp, err := h.Call(context.Background(), newReq(t, 1, "ping"))
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected rpc error: %v", resp.Error)
	}
	if string(resp.Result) != `{"ok":true}` {
		t.Errorf("unexpected result: %s", resp.Result)
	}
	if h.session != "sess-1" {
		t.Errorf("session id not captured, got %q", h.session)
	}
}

func TestHTTPSSEResponseMatchesByID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// An unrelated message first, then the one we asked for.
		fmt.Fprint(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":999,\"result\":{\"other\":true}}\n\n")
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"matched\":true}}\n\n")
	}))
	defer srv.Close()

	h := NewHTTP(srv.URL)
	resp, err := h.Call(context.Background(), newReq(t, 7, "slow"))
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if string(resp.Result) != `{"matched":true}` {
		t.Errorf("sse did not match by id, got: %s", resp.Result)
	}
}

func TestHTTPNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()

	h := NewHTTP(srv.URL)
	if _, err := h.Call(context.Background(), newReq(t, 1, "ping")); err == nil {
		t.Fatal("expected error on 403")
	}
}
