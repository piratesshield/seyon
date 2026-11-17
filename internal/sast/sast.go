// Package sast is Seyon's white-box analyzer. It walks a source tree and runs
// language and artifact analyzers over it: a native go/ast taint analyzer for
// Go, pattern-based source analysis for Python/JavaScript/TypeScript, secrets
// detection across all text files, dependency-manifest checks, and
// Dockerfile/IaC posture checks. It reads source only and executes nothing.
package sast

import (
	"context"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"seyon/internal/findings"
)

// maxFileSize bounds a single file read, so a huge blob cannot exhaust memory.
const maxFileSize = 4 << 20

// skipDirs are directories never worth scanning.
var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, ".venv": true,
	"venv": true, "dist": true, "build": true, "__pycache__": true,
}

// Options configures an Analyzer. The zero value is the safe, fully offline
// default: dependency checks use only the embedded advisory set.
type Options struct {
	// OSV enables live OSV.dev lookups for dependency manifests. It is opt-in
	// because it sends package coordinates (ecosystem, name, version) over the
	// network; it never transmits source code or file contents.
	OSV bool
	// OSVBaseURL overrides the OSV API root (tests point this at a local
	// server). Empty uses the public endpoint.
	OSVBaseURL string
	// HTTPClient overrides the HTTP client used for OSV (tests inject one).
	// Nil uses a default client with a bounded timeout.
	HTTPClient *http.Client
}

// Analyzer runs the white-box detectors over a directory tree.
type Analyzer struct {
	patterns *patternEngine
	secrets  *secretScanner
	advisory *advisoryDB
	osv      *osvClient // nil unless live OSV lookups are enabled
}

// NewAnalyzer builds a white-box analyzer with the embedded rule packs, secret
// patterns, and advisory data, configured by opts.
func NewAnalyzer(opts Options) (*Analyzer, error) {
	pe, err := loadPatternEngine()
	if err != nil {
		return nil, err
	}
	adb, err := loadAdvisoryDB()
	if err != nil {
		return nil, err
	}
	a := &Analyzer{
		patterns: pe,
		secrets:  newSecretScanner(),
		advisory: adb,
	}
	if opts.OSV {
		a.osv = newOSVClient(opts.OSVBaseURL, opts.HTTPClient)
	}
	return a, nil
}

// AnalyzeDir walks root, runs the per-file detectors, then resolves the
// dependency coordinates it gathered against the embedded advisory set or, when
// enabled, a live OSV query. Finding locations are made repo-relative. The
// context bounds any network lookups.
func (a *Analyzer) AnalyzeDir(ctx context.Context, root string) ([]findings.Finding, error) {
	var out []findings.Finding
	var coords []depCoord
	var goSources []goSource
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries rather than aborting the scan
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel := relPath(root, path)
		ff, cc := a.analyzeFile(rel, data)
		out = append(out, ff...)
		coords = append(coords, cc...)
		if strings.EqualFold(filepath.Ext(path), ".go") {
			goSources = append(goSources, goSource{rel: rel, data: data})
		}
		return nil
	})
	// Go is analyzed over the whole tree so a tool registered in one file can
	// anchor a sink found in another.
	goFindings := analyzeGoTree(goSources)
	for i := range goFindings {
		src := goFindings[i].Target.Source
		if idx := strings.Index(src, ":"); idx > 0 {
			src = src[:idx]
		}
		if isTestFile(src) {
			goFindings[i].Severity = findings.SeverityInfo
			goFindings[i].Evidence.Note = "[test file] " + goFindings[i].Evidence.Note
		}
	}
	out = append(out, goFindings...)
	out = append(out, a.matchDeps(ctx, coords)...)
	findings.Sort(out)
	return out, walkErr
}

// matchDeps resolves dependency coordinates into D1 findings. With OSV enabled
// it queries live and, on failure, falls back to the embedded set while
// recording the degradation honestly. Offline it uses the embedded set alone.
func (a *Analyzer) matchDeps(ctx context.Context, coords []depCoord) []findings.Finding {
	if len(coords) == 0 {
		return nil
	}
	if a.osv != nil {
		fs, err := a.osv.scan(ctx, coords)
		if err != nil {
			out := a.advisory.matchCoords(coords)
			return append(out, osvUnavailableFinding(err))
		}
		return fs
	}
	return a.advisory.matchCoords(coords)
}

// analyzeFile dispatches a single file to the applicable analyzers, returning
// its findings plus any dependency coordinates to resolve after the walk.
func (a *Analyzer) analyzeFile(rel string, data []byte) ([]findings.Finding, []depCoord) {
	var out []findings.Finding
	var coords []depCoord
	base := filepath.Base(rel)
	ext := strings.ToLower(filepath.Ext(rel))

	// Secrets run over every text file.
	if isText(data) {
		out = append(out, a.secrets.scan(rel, data)...)
	}

	switch ext {
	case ".py":
		if fs, ok := analyzePython(rel, data); ok {
			out = append(out, fs...)
		} else {
			out = append(out, a.patterns.scan(rel, "python", data)...)
		}
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx":
		if fs, ok := analyzeJS(rel, data); ok {
			out = append(out, fs...)
		} else {
			out = append(out, a.patterns.scan(rel, "javascript", data)...)
		}
	}

	switch base {
	case "go.mod":
		coords = append(coords, parseGoMod(rel, data)...)
	case "package.json":
		coords = append(coords, parsePackageJSON(rel, data)...)
		out = append(out, scanNPMScripts(rel, data)...)
	case "requirements.txt":
		coords = append(coords, parseRequirements(rel, data)...)
	}
	if base == "Dockerfile" || strings.HasSuffix(base, ".dockerfile") {
		out = append(out, scanDockerfile(rel, data)...)
	}

	if isSkillFile(rel) {
		out = append(out, scanSkillFile(rel, data)...)
	}
	if isHooksFile(rel) {
		out = append(out, scanHooksFile(rel, data)...)
	}
	out = downgradeTestFindings(rel, out)
	return out, coords
}

var testPathRe = regexp.MustCompile(`(?i)(^|/)tests?/|[._]test\.|[._]spec\.|__tests?__|__mocks?__`)

func isTestFile(rel string) bool {
	return testPathRe.MatchString(rel)
}

func downgradeTestFindings(rel string, ff []findings.Finding) []findings.Finding {
	if !isTestFile(rel) {
		return ff
	}
	for i := range ff {
		ff[i].Severity = findings.SeverityInfo
		ff[i].Evidence.Note = "[test file] " + ff[i].Evidence.Note
	}
	return ff
}

func relPath(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return rel
	}
	return path
}

// isText reports whether data looks like text (no NUL in the first chunk).
func isText(data []byte) bool {
	n := len(data)
	if n > 1024 {
		n = 1024
	}
	for _, b := range data[:n] {
		if b == 0 {
			return false
		}
	}
	return true
}
