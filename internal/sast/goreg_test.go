package sast

import (
	"testing"

	"seyon/internal/findings"
)

// findClass returns the first finding of the given class, or nil.
func findClass(fs []findings.Finding, class string) *findings.Finding {
	for i := range fs {
		if fs[i].Class == class {
			return &fs[i]
		}
	}
	return nil
}

func TestToolAnchoringNamedHandlerSameFile(t *testing.T) {
	src := `package srv
import "os/exec"
func register(s *Server) { s.AddTool(mcp.NewTool("run_command", mcp.WithDescription("x")), handleRun) }
func handleRun(cmd string) error { return exec.Command("sh", "-c", cmd).Run() }
`
	fs := analyzeGoTree([]goSource{{rel: "server.go", data: []byte(src)}})
	c1 := findClass(fs, "C1")
	if c1 == nil {
		t.Fatalf("expected a C1 finding, got %+v", fs)
	}
	if c1.Target.Tool != "run_command" {
		t.Errorf("C1 tool = %q, want run_command", c1.Target.Tool)
	}
}

func TestToolAnchoringCrossFileNamedHandler(t *testing.T) {
	reg := `package srv
func register(s *Server) { s.AddTool(mcp.NewTool("fetch_url"), fetchHandler) }
`
	impl := `package srv
import "net/http"
func fetchHandler(u string) (*http.Response, error) { return http.Get(u) }
`
	fs := analyzeGoTree([]goSource{
		{rel: "register.go", data: []byte(reg)},
		{rel: "handlers.go", data: []byte(impl)},
	})
	c3 := findClass(fs, "C3")
	if c3 == nil {
		t.Fatalf("expected a C3 finding, got %+v", fs)
	}
	if c3.Target.Tool != "fetch_url" {
		t.Errorf("C3 tool = %q, want fetch_url (anchored across files)", c3.Target.Tool)
	}
	if c3.Target.Source == "" {
		t.Error("tool-anchored finding should still carry a file:line source")
	}
}

func TestToolAnchoringInlineClosure(t *testing.T) {
	src := `package srv
import "os/exec"
func register(s *Server) {
	s.AddTool(mcp.NewTool("shell"), func(cmd string) error {
		return exec.Command("sh", "-c", cmd).Run()
	})
}
`
	fs := analyzeGoTree([]goSource{{rel: "server.go", data: []byte(src)}})
	c1 := findClass(fs, "C1")
	if c1 == nil {
		t.Fatalf("expected a C1 finding, got %+v", fs)
	}
	if c1.Target.Tool != "shell" {
		t.Errorf("C1 tool = %q, want shell (inline closure)", c1.Target.Tool)
	}
}

func TestToolAnchoringStructLiteralOfficialSDK(t *testing.T) {
	src := `package srv
import "os"
func register() { mcp.AddTool(srv, &mcp.Tool{Name: "read_file"}, readHandler) }
func readHandler(path string) ([]byte, error) { return os.ReadFile(path) }
`
	fs := analyzeGoTree([]goSource{{rel: "server.go", data: []byte(src)}})
	c2 := findClass(fs, "C2")
	if c2 == nil {
		t.Fatalf("expected a C2 finding, got %+v", fs)
	}
	if c2.Target.Tool != "read_file" {
		t.Errorf("C2 tool = %q, want read_file (&mcp.Tool{Name:...})", c2.Target.Tool)
	}
}

func TestUnregisteredHandlerIsNotAnchored(t *testing.T) {
	src := `package srv
import "os/exec"
func helper(x string) error { return exec.Command("sh", "-c", x).Run() }
`
	fs := analyzeGoTree([]goSource{{rel: "util.go", data: []byte(src)}})
	c1 := findClass(fs, "C1")
	if c1 == nil {
		t.Fatalf("expected a C1 finding, got %+v", fs)
	}
	if c1.Target.Tool != "" {
		t.Errorf("unregistered function should not be tool-anchored, got %q", c1.Target.Tool)
	}
}
