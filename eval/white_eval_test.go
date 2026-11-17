package eval_test

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"seyon/internal/findings"
	"seyon/internal/sast"
)

// baseFile strips the ":line" suffix from a finding's Source and returns the
// file's base name, so expectations are robust to brittle line numbers.
func baseFile(f findings.Finding) string {
	src := f.Target.Source
	if i := strings.LastIndex(src, ":"); i >= 0 {
		src = src[:i]
	}
	return filepath.Base(src)
}

// classFileSet collapses findings to the set of (class, base-file) pairs.
func classFileSet(fs []findings.Finding) map[string]bool {
	set := map[string]bool{}
	for _, f := range fs {
		set[f.Class+"@"+baseFile(f)] = true
	}
	return set
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func analyze(t *testing.T, dir string) []findings.Finding {
	t.Helper()
	a, err := sast.NewAnalyzer(sast.Options{})
	if err != nil {
		t.Fatalf("new analyzer: %v", err)
	}
	fs, err := a.AnalyzeDir(context.Background(), filepath.Join("..", "lab", "whitebox", "testdata", dir))
	if err != nil {
		t.Fatalf("analyze %s: %v", dir, err)
	}
	return fs
}

func TestWhiteBoxVulnFixtures(t *testing.T) {
	fs := analyze(t, "vuln")
	got := classFileSet(fs)
	want := map[string]bool{
		// Go taint analysis (handlers.go)
		"C1@handlers.go": true,
		"C2@handlers.go": true,
		"C3@handlers.go": true,
		"C4@handlers.go": true,
		"C6@handlers.go": true,
		// Python patterns (app.py)
		"C1@app.py": true,
		"C3@app.py": true,
		// JavaScript patterns (server.js)
		"C1@server.js": true,
		// Dockerfile posture
		"D3@Dockerfile": true,
		// Dependency + supply-chain (package.json)
		"D1@package.json": true,
		"D2@package.json": true,
		// Dependency (requirements.txt)
		"D1@requirements.txt": true,
		// Secret (config.env)
		"C5@config.env": true,
	}

	gotKeys, wantKeys := keys(got), keys(want)
	for _, k := range wantKeys {
		if !got[k] {
			t.Errorf("missing expected finding: %s", k)
		}
	}
	for _, k := range gotKeys {
		if !want[k] {
			t.Errorf("unexpected finding (false positive): %s", k)
		}
	}
	if t.Failed() {
		t.Logf("got:  %v", gotKeys)
		t.Logf("want: %v", wantKeys)
	}
}

func TestWhiteBoxSafeTwinsHaveNoFindings(t *testing.T) {
	fs := analyze(t, "safe")
	if len(fs) != 0 {
		var got []string
		for _, f := range fs {
			got = append(got, f.Class+"@"+f.Target.Source)
		}
		sort.Strings(got)
		t.Errorf("safe tree should yield no findings, got %d: %v", len(fs), got)
	}
}
