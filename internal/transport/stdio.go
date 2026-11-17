// Package transport provides MCP transports: stdio (a spawned local process)
// and Streamable HTTP/SSE. Both satisfy mcp.Transport.
package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"

	"seyon/internal/mcp"
)

// maxLine bounds a single newline-delimited JSON-RPC message (8 MiB). MCP stdio
// framing is one JSON object per line with no embedded newlines.
const maxLine = 8 << 20

// Stdio speaks MCP over a child process's stdin/stdout using newline-delimited
// JSON. A background goroutine reads responses and dispatches them to callers
// by request id, so Call is safe for sequential use by one Client.
type Stdio struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	writeM sync.Mutex

	mu       sync.Mutex
	pending  map[string]chan *mcp.Response
	closed   bool
	readDone bool
	readErr  error
	done     chan struct{}
}

// SpawnStdio starts the given command and returns a connected transport. The
// caller is responsible for ensuring the command is safe to run; Seyon's engine
// only spawns untrusted targets through SpawnStdioCmd with a sandbox plan.
func SpawnStdio(ctx context.Context, name string, args ...string) (*Stdio, error) {
	return SpawnStdioCmd(exec.CommandContext(ctx, name, args...), name)
}

// SpawnStdioCmd starts a pre-built command as an MCP stdio transport. It lets
// the engine apply a sandbox (network-isolation wrapper, working directory)
// before the child is started. label names the command for error messages.
func SpawnStdioCmd(cmd *exec.Cmd, label string) (*Stdio, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdio: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdio: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("stdio: start %s: %w", label, err)
	}
	s := &Stdio{
		cmd:     cmd,
		stdin:   stdin,
		pending: make(map[string]chan *mcp.Response),
		done:    make(chan struct{}),
	}
	go s.readLoop(stdout)
	return s, nil
}

func idKey(raw json.RawMessage) string { return string(raw) }

func (s *Stdio) readLoop(r io.Reader) {
	defer close(s.done)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var resp mcp.Response
		if err := json.Unmarshal(line, &resp); err != nil {
			// Not a valid JSON-RPC message; ignore (could be stray stderr-like
			// noise on stdout). The protocol layer surfaces real errors.
			continue
		}
		if len(resp.ID) == 0 {
			// A notification from the server; no waiter. Ignored in Phase 0.
			continue
		}
		s.deliver(idKey(resp.ID), &resp)
	}
	err := sc.Err()
	s.mu.Lock()
	s.readErr = err
	s.readDone = true
	for _, ch := range s.pending {
		close(ch)
	}
	s.pending = map[string]chan *mcp.Response{}
	s.mu.Unlock()
}

func (s *Stdio) deliver(key string, resp *mcp.Response) {
	s.mu.Lock()
	ch, ok := s.pending[key]
	if ok {
		delete(s.pending, key)
	}
	s.mu.Unlock()
	if ok {
		ch <- resp
	}
}

func (s *Stdio) register(key string) (chan *mcp.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("stdio: transport closed")
	}
	if s.readDone {
		if s.readErr != nil {
			return nil, fmt.Errorf("stdio: connection closed: %w", s.readErr)
		}
		return nil, fmt.Errorf("stdio: connection closed by server")
	}
	ch := make(chan *mcp.Response, 1)
	s.pending[key] = ch
	return ch, nil
}

func (s *Stdio) unregister(key string) {
	s.mu.Lock()
	delete(s.pending, key)
	s.mu.Unlock()
}

func (s *Stdio) write(req mcp.Request) error {
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("stdio: marshal request: %w", err)
	}
	data = append(data, '\n')
	s.writeM.Lock()
	defer s.writeM.Unlock()
	if _, err := s.stdin.Write(data); err != nil {
		return fmt.Errorf("stdio: write: %w", err)
	}
	return nil
}

// Call sends req and waits for the matching response or ctx cancellation.
func (s *Stdio) Call(ctx context.Context, req mcp.Request) (*mcp.Response, error) {
	key := idKey(req.ID)
	ch, err := s.register(key)
	if err != nil {
		return nil, err
	}
	if err := s.write(req); err != nil {
		s.unregister(key)
		return nil, err
	}
	select {
	case <-ctx.Done():
		s.unregister(key)
		return nil, ctx.Err()
	case resp, ok := <-ch:
		if !ok {
			s.mu.Lock()
			rerr := s.readErr
			s.mu.Unlock()
			if rerr != nil {
				return nil, fmt.Errorf("stdio: connection closed: %w", rerr)
			}
			return nil, fmt.Errorf("stdio: connection closed before response")
		}
		return resp, nil
	}
}

// Notify sends a notification and returns once it is written. The context is
// unused: stdio writes are local and non-blocking under normal operation.
func (s *Stdio) Notify(_ context.Context, req mcp.Request) error {
	return s.write(req)
}

// Close shuts stdin, waits for the process to exit, and stops the reader.
func (s *Stdio) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	// Close stdin so the child sees EOF and exits; then let the reader drain
	// stdout to EOF before Wait, which is the safe order for StdoutPipe.
	_ = s.stdin.Close()
	<-s.done
	return s.cmd.Wait()
}
