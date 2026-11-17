package source

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxArchiveBytes caps total extracted size to avoid a zip bomb.
const maxArchiveBytes = 512 << 20

// Unzip extracts a .zip archive to a fresh temp directory and returns a
// resolved handle plus a cleanup function. It guards against zip-slip
// (entries that escape the destination) and bounds total output size.
func Unzip(path string) (*Resolved, func(), error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil, fmt.Errorf("source: open zip %q: %w", path, err)
	}
	defer func() { _ = zr.Close() }()

	dir, err := os.MkdirTemp("", "seyon-zip-")
	if err != nil {
		return nil, nil, fmt.Errorf("source: tempdir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	var total int64
	for _, f := range zr.File {
		dest := filepath.Join(dir, f.Name)
		rel, err := filepath.Rel(dir, dest)
		if err != nil || strings.HasPrefix(rel, "..") {
			cleanup()
			return nil, nil, fmt.Errorf("source: zip entry %q escapes destination", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(dest, 0o755); err != nil {
				cleanup()
				return nil, nil, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			cleanup()
			return nil, nil, err
		}
		written, err := extractOne(f, dest, maxArchiveBytes-total)
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		total += written
		if total > maxArchiveBytes {
			cleanup()
			return nil, nil, fmt.Errorf("source: archive exceeds size limit")
		}
	}
	return &Resolved{Kind: KindDir, Root: dir, Origin: "archive:" + filepath.Base(path)}, cleanup, nil
}

func extractOne(f *zip.File, dest string, limit int64) (int64, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, err
	}
	defer func() { _ = rc.Close() }()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	defer func() { _ = out.Close() }()
	n, err := io.Copy(out, io.LimitReader(rc, limit+1))
	if err != nil {
		return n, err
	}
	return n, nil
}
