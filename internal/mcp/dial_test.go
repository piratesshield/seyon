package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"seyon/internal/mcp"
	// Side-effect import registers the transport constructors with the mcp package.
	_ "seyon/internal/transport"
)

// httpStub serves Streamable HTTP MCP: one POST, JSON response. Rejects GET so
// a probing dialer that tries SSE first against this host sees 405.
func httpStub() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		if req.Method == "initialize" {
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"stub-http","version":"1"}}}`, req.ID)
			return
		}
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, req.ID)
	}))
}

// legacyOnlyStub serves the two-URL SSE pattern and rejects any POST to the
// SSE URL with 405, so the Streamable-HTTP branch has to give up and fall
// back to SSE.
func legacyOnlyStub(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	ready := make(chan struct{})
	outbox := make(chan string, 8)
	mux := http.NewServeMux()
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		fmt.Fprint(w, "event: endpoint\ndata: /msg?sid=1\n\n")
		fl.Flush()
		select {
		case <-ready:
		default:
			close(ready)
		}
		for {
			select {
			case frame := <-outbox:
				fmt.Fprint(w, frame)
				fl.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	mux.HandleFunc("/msg", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		<-ready
		if req.Method == "initialize" {
			outbox <- fmt.Sprintf(
				"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"stub-sse\",\"version\":\"1\"}}}\n\n",
				req.ID)
			return
		}
		if req.Method == "server/discover" {
			// Simulate a legacy server rejecting discover so the client
			// falls back to initialize().
			outbox <- fmt.Sprintf(
				"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":%s,\"error\":{\"code\":-32601,\"message\":\"method not found\"}}\n\n",
				req.ID)
			return
		}
		outbox <- fmt.Sprintf("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{}}\n\n", req.ID)
	})
	srv.Config.Handler = mux
	srv.Start()
	return srv
}

func TestDialPicksStreamableHTTP(t *testing.T) {
	srv := httpStub()
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := mcp.Dial(ctx, srv.URL, mcp.DialOptions{DialTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = res.Client.Close() }()
	if res.Kind != mcp.DialStreamableHTTP {
		t.Errorf("want streamable-http, got %s", res.Kind)
	}
	if res.Server.Name != "stub-http" {
		t.Errorf("wrong server identity: %+v", res.Server)
	}
}

func TestDialFallsBackToLegacySSE(t *testing.T) {
	srv := legacyOnlyStub(t)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := mcp.Dial(ctx, srv.URL+"/sse", mcp.DialOptions{DialTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = res.Client.Close() }()
	if res.Kind != mcp.DialLegacySSE {
		t.Errorf("want legacy-sse, got %s", res.Kind)
	}
	if res.Server.Name != "stub-sse" {
		t.Errorf("wrong server identity: %+v", res.Server)
	}
}

func TestDialShortCircuitsOnAuthChallenge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := mcp.Dial(ctx, srv.URL, mcp.DialOptions{DialTimeout: 2 * time.Second, ProbePaths: mcp.DefaultProbePaths})
	if err == nil {
		t.Fatalf("expected error on 401")
	}
	// Must stop after the first attempt — not retry across every candidate URL.
	if !strings.Contains(err.Error(), "1 attempt") {
		t.Errorf("auth challenge should short-circuit after first attempt, got: %v", err)
	}
	var httpErr *mcp.HTTPStatusError
	if !errors.As(err, &httpErr) || httpErr.Code != http.StatusUnauthorized {
		t.Errorf("expected wrapped 401, got: %v", err)
	}
}

func TestCandidateURLsDedupesAndRespectsProbe(t *testing.T) {
	got, err := mcp.CandidateURLsForTest("https://example.com/mcp", []string{"/mcp", "/sse", "/"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://example.com/mcp",
		"https://example.com/sse",
		"https://example.com/",
	}
	if len(got) != len(want) {
		t.Fatalf("want %v got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("at %d: want %q got %q", i, want[i], got[i])
		}
	}
}
