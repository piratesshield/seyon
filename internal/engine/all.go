package engine

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"seyon/internal/correlate"
	"seyon/internal/detect"
	"seyon/internal/findings"
	"seyon/internal/manifest"
	"seyon/internal/report"
	"seyon/internal/sast"
	"seyon/internal/source"
	"seyon/internal/surface"
)

// configNames are the basenames that look like an MCP client configuration or a
// captured surface snapshot worth feeding to the gray-box analyzer when a whole
// source tree is submitted.
var configNames = map[string]bool{
	"mcp.json":                   true,
	".mcp.json":                  true,
	"claude_desktop_config.json": true,
}

// CombinedScan runs the applicable static modes over a single submitted source
// tree — white-box SAST over the code, and gray-box analysis over any MCP
// configuration or surface snapshots discovered in the tree — then correlates
// across them. It is the "one submission, every applicable mode" entry point.
func CombinedScan(ctx context.Context, version string, resolved *source.Resolved, ruleDirs []string, osv bool) (*report.Report, error) {
	r := report.New(version, resolved.Origin, []findings.Mode{findings.ModeWhite, findings.ModeGray})
	if resolved.Kind != source.KindDir {
		err := fmt.Errorf("combined scan needs a source directory, got %s", resolved.Kind)
		r.AddStage("ingest", findings.StageError, err.Error())
		r.Finalize()
		return r, err
	}

	// White-box SAST over the whole tree.
	sa, err := sast.NewAnalyzer(sast.Options{OSV: osv})
	if err != nil {
		r.Finalize()
		return r, fmt.Errorf("combined: init sast: %w", err)
	}
	before := len(r.Findings)
	if wf, werr := sa.AnalyzeDir(ctx, resolved.Root); werr != nil {
		r.AddStage("sast", findings.StageError, werr.Error())
	} else {
		r.Add(wf...)
		r.AddStage("sast", stageStatus(len(r.Findings)-before), "static source analysis")
	}

	// Gray-box over any discovered configs / surface snapshots.
	da, err := detect.NewAnalyzer(ruleDirs...)
	if err != nil {
		r.Finalize()
		return r, fmt.Errorf("combined: load rules: %w", err)
	}
	configs := discoverConfigs(resolved.Root)
	before = len(r.Findings)
	for _, path := range configs {
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			continue
		}
		origin := relForReport(resolved.Root, path)
		if manifest.Looks(data) {
			if cfg, perr := manifest.Parse(data); perr == nil {
				r.Add(da.Config(cfg)...)
			}
		}
		if surface.Looks(data) {
			if s, perr := surface.Parse(data, origin); perr == nil {
				r.Add(da.Surface(s)...)
			}
		}
	}
	r.AddStage("gray", stageStatus(len(r.Findings)-before),
		fmt.Sprintf("%d config/surface file(s) discovered", len(configs)))

	// Cross-mode correlation over the combined findings.
	corr := correlate.Findings(r.Findings)
	r.Add(corr...)
	r.AddStage("correlate", stageStatus(len(corr)),
		fmt.Sprintf("%d cross-mode correlation(s)", len(corr)))

	r.Finalize()
	return r, nil
}

// discoverConfigs walks root for files that look like an MCP config or surface
// snapshot. It skips the same vendored/build directories as the SAST walker and
// bounds how many files it returns, so a pathological tree cannot blow up.
func discoverConfigs(root string) []string {
	const maxConfigs = 64
	skip := map[string]bool{
		".git": true, "vendor": true, "node_modules": true, ".venv": true,
		"venv": true, "dist": true, "build": true, "__pycache__": true,
	}
	var out []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if configNames[name] || strings.HasSuffix(name, ".mcp.json") {
			out = append(out, path)
			if len(out) >= maxConfigs {
				return filepath.SkipAll
			}
		}
		return nil
	})
	return out
}

func relForReport(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return rel
	}
	return path
}
