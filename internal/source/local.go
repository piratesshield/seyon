package source

import (
	"fmt"
	"os"
	"path/filepath"
)

// Local resolves a local filesystem path (a directory or a single file) into a
// normalized handle. It does not read or execute anything; it only validates
// and canonicalizes the path.
func Local(path string) (*Resolved, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("source: resolve path %q: %w", path, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("source: stat %q: %w", abs, err)
	}
	kind := KindFile
	if info.IsDir() {
		kind = KindDir
	}
	return &Resolved{
		Kind:   kind,
		Root:   abs,
		Origin: "local:" + abs,
	}, nil
}
