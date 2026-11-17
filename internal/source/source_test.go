package source

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalDirAndFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	rd, err := Local(dir)
	if err != nil {
		t.Fatalf("local dir: %v", err)
	}
	if rd.Kind != KindDir {
		t.Errorf("expected dir kind, got %s", rd.Kind)
	}
	if !filepath.IsAbs(rd.Root) {
		t.Errorf("root not absolute: %s", rd.Root)
	}

	rf, err := Local(file)
	if err != nil {
		t.Fatalf("local file: %v", err)
	}
	if rf.Kind != KindFile {
		t.Errorf("expected file kind, got %s", rf.Kind)
	}
}

func TestLocalMissing(t *testing.T) {
	if _, err := Local(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestParseEndpoint(t *testing.T) {
	stdio, err := ParseEndpoint("stdio:./bin/server --flag x")
	if err != nil {
		t.Fatalf("stdio parse: %v", err)
	}
	if stdio.Scheme != SchemeStdio || stdio.Command != "./bin/server" {
		t.Errorf("bad stdio parse: %+v", stdio)
	}
	if len(stdio.Args) != 2 || stdio.Args[0] != "--flag" {
		t.Errorf("bad stdio args: %v", stdio.Args)
	}

	h, err := ParseEndpoint("https://mcp.example.com/rpc")
	if err != nil {
		t.Fatalf("http parse: %v", err)
	}
	if h.Scheme != SchemeHTTP || h.URL != "https://mcp.example.com/rpc" {
		t.Errorf("bad http parse: %+v", h)
	}

	if _, err := ParseEndpoint("ftp://x"); err == nil {
		t.Error("expected error for unknown scheme")
	}
	if _, err := ParseEndpoint("stdio:"); err == nil {
		t.Error("expected error for empty stdio command")
	}
}
