package source

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// makeRepo initializes a local git repo with a single committed file and
// returns its path. A local repo lets GitClone be tested without network.
func makeRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "mcp.json"), []byte(`{"mcpServers":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "mcp.json")
	run("commit", "-q", "-m", "init")
	return dir
}

func TestGitCloneAndReadFile(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	repo := makeRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resolved, cleanup, err := GitClone(ctx, repo, "")
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	defer cleanup()

	data, err := ReadRepoFile(resolved, "mcp.json")
	if err != nil {
		t.Fatalf("read repo file: %v", err)
	}
	if string(data) != `{"mcpServers":{}}` {
		t.Errorf("unexpected content: %s", data)
	}

	// Path traversal must be refused.
	if _, err := ReadRepoFile(resolved, "../../etc/passwd"); err == nil {
		t.Error("expected path-traversal read to be refused")
	}
}
