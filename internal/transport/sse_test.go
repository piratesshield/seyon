package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"seyon/internal/mcp"
)

// sseStub is a minimal MCP legacy-SSE server for tests. All writes to the
// event-stream happen on the GET handler's goroutine; the POST handler enqueues
// messages via a channel, so there is only one writer at a time.
type sseStub struct {
	*httptest.Server
	ready    chan struct{}
	outbox   chan string
	handler  func(req mcp.Request) mcp.Response
	rejectGE bool // reject the initial GET with 403, for error-path tests
}

func newSSEStub(handler func(req mcp.Request) mcp.Response) *sseStub {
	stub := &sseStub{
		ready:   make(chan struct{}),
		outbox:  make(chan string, 32),
		handler: handler,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		if stub.rejectGE {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		fl, ok := w.(http.Flusher)
		if !ok {
			return
		}
		fmt.Fprint(w, "event: endpoint\ndata: /messages?sessionId=abc\n\n")
		fl.Flush()
		close(stub.ready)
		for {
			select {
			case frame := <-stub.outbox:
				fmt.Fprint(w, frame)
				fl.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	mux.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		var req mcp.Request
		if err := json.Unmarshal(body, &req); err != nil {
			return
		}
		resp := stub.handler(req)
		data, _ := json.Marshal(resp)
		<-stub.ready
		select {
		case stub.outbox <- fmt.Sprintf("event: message\ndata: %s\n\n", data):
		case <-r.Context().Done():
		}
	})
	stub.Server = httptest.NewServer(mux)
	return stub
}

// pushRaw enqueues an arbitrary SSE chunk for the GET handler to flush.
func (s *sseStub) pushRaw(frame string) {
	<-s.ready
	select {
	case s.outbox <- frame:
	case <-time.After(time.Second):
	}
}

func TestSSECallRoundTrip(t *testing.T) {
	stub := newSSEStub(func(req mcp.Request) mcp.Response {
		return mcp.Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  json.RawMessage(`{"ok":true}`),
		}
	})
	defer stub.Close()

	tr := NewLegacySSE(stub.URL + "/sse")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tr.Dial(ctx); err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = tr.Close() }()

	resp, err := tr.Call(ctx, mcp.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "ping"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if string(resp.Result) != `{"ok":true}` {
		t.Errorf("unexpected result: %s", resp.Result)
	}
}

func TestSSEConcurrentCalls(t *testing.T) {
	stub := newSSEStub(func(req mcp.Request) mcp.Response {
		return mcp.Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  json.RawMessage(fmt.Sprintf(`{"echo":%s}`, req.ID)),
		}
	})
	defer stub.Close()

	tr := NewLegacySSE(stub.URL + "/sse")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := tr.Dial(ctx); err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = tr.Close() }()

	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 1; i <= n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := tr.Call(ctx, mcp.Request{
				JSONRPC: "2.0",
				ID:      json.RawMessage(fmt.Sprintf(`%d`, i)),
				Method:  "ping",
			})
			if err != nil {
				errs <- err
				return
			}
			want := fmt.Sprintf(`{"echo":%d}`, i)
			if string(resp.Result) != want {
				errs <- fmt.Errorf("want %s got %s", want, resp.Result)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestSSEDialRejectsNon2xx(t *testing.T) {
	stub := newSSEStub(nil)
	stub.rejectGE = true
	defer stub.Close()

	tr := NewLegacySSE(stub.URL + "/sse")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err := tr.Dial(ctx)
	if err == nil {
		t.Fatalf("expected error on 403")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention status, got %v", err)
	}
}

func TestSSESkipsCommentsAndKeepAlives(t *testing.T) {
	stub := newSSEStub(func(req mcp.Request) mcp.Response {
		return mcp.Response{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`"ok"`)}
	})
	defer stub.Close()

	tr := NewLegacySSE(stub.URL + "/sse")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tr.Dial(ctx); err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = tr.Close() }()

	// Push SSE comment line and an unknown-event frame; reader should ignore
	// them and still serve the next call correctly.
	stub.pushRaw(": keep-alive\n\n")
	stub.pushRaw("event: log\ndata: ignored\n\n")

	resp, err := tr.Call(ctx, mcp.Request{JSONRPC: "2.0", ID: json.RawMessage(`7`), Method: "ping"})
	if err != nil {
		t.Fatalf("call after noise: %v", err)
	}
	if string(resp.Result) != `"ok"` {
		t.Errorf("unexpected result: %s", resp.Result)
	}
}
