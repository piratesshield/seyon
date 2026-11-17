package source

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// GitClone shallow-clones a repository to a fresh temp directory and returns a
// resolved handle plus a cleanup function the caller must invoke. It uses the
// git CLI; ref may be empty for the default branch. A local path or file:// URL
// works too, which is how it is tested without network access.
//
// The clone fetches code only; nothing in the repository is executed.
func GitClone(ctx context.Context, repo, ref string) (*Resolved, func(), error) {
	dir, err := os.MkdirTemp("", "seyon-git-")
	if err != nil {
		return nil, nil, fmt.Errorf("source: tempdir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	args := []string{"clone", "--depth", "1"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, repo, dir)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("source: git clone %s: %w: %s", repo, err, string(out))
	}

	origin := "git:" + repo
	if ref != "" {
		origin += "@" + ref
	}
	return &Resolved{Kind: KindDir, Root: dir, Origin: origin}, cleanup, nil
}

// ReadRepoFile reads a file at a repo-relative path from a resolved checkout,
// guarding against path traversal outside the checkout root.
func ReadRepoFile(r *Resolved, relPath string) ([]byte, error) {
	clean := filepath.Clean(relPath)
	full := filepath.Join(r.Root, clean)
	rel, err := filepath.Rel(r.Root, full)
	if err != nil || rel == ".." || filepath.IsAbs(clean) || hasDotDotPrefix(rel) {
		return nil, fmt.Errorf("source: path %q escapes the checkout", relPath)
	}
	return os.ReadFile(full)
}

func hasDotDotPrefix(rel string) bool {
	return rel == ".." || (len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator))
}
