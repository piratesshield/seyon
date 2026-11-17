package engine

import (
	"fmt"

	"seyon/internal/baseline"
	"seyon/internal/detect"
	"seyon/internal/findings"
	"seyon/internal/manifest"
	"seyon/internal/report"
	"seyon/internal/surface"
)

// GrayScan runs the gray-box analyzer over submitted bytes, which may be an MCP
// client configuration (mcp.json), a surface snapshot (tools/list), or both. It
// records an honest stage status per input kind.
func GrayScan(version string, data []byte, origin string) (*report.Report, error) {
	return GrayScanWithRules(version, data, origin, nil)
}

// GrayScanWithRules is GrayScan with additional external rule-pack directories.
func GrayScanWithRules(version string, data []byte, origin string, ruleDirs []string) (*report.Report, error) {
	r := report.New(version, origin, []findings.Mode{findings.ModeGray})
	a, err := detect.NewAnalyzer(ruleDirs...)
	if err != nil {
		return nil, fmt.Errorf("gray: load rules: %w", err)
	}

	matched := false
	if manifest.Looks(data) {
		cfg, perr := manifest.Parse(data)
		if perr != nil {
			r.AddStage("manifest", findings.StageError, perr.Error())
		} else {
			matched = true
			before := len(r.Findings)
			r.Add(a.Config(cfg)...)
			r.AddStage("manifest", stageStatus(len(r.Findings)-before),
				fmt.Sprintf("%d server(s)", len(cfg.Servers)))
		}
	}
	if surface.Looks(data) {
		s, perr := surface.Parse(data, origin)
		if perr != nil {
			r.AddStage("surface", findings.StageError, perr.Error())
		} else {
			matched = true
			before := len(r.Findings)
			r.Add(a.Surface(s)...)
			r.AddStage("surface", stageStatus(len(r.Findings)-before),
				fmt.Sprintf("%d tools, %d prompts", len(s.Tools), len(s.Prompts)))
		}
	}

	if !matched {
		err := fmt.Errorf("input is neither an MCP configuration nor a surface snapshot")
		r.AddStage("ingest", findings.StageError, err.Error())
		r.Finalize()
		return r, err
	}
	r.Finalize()
	return r, nil
}

// DriftScan compares a surface snapshot against a trusted baseline (B4).
func DriftScan(version string, base *baseline.Baseline, data []byte, origin string) (*report.Report, error) {
	r := report.New(version, origin, []findings.Mode{findings.ModeGray})
	s, err := surface.Parse(data, origin)
	if err != nil {
		r.AddStage("surface", findings.StageError, err.Error())
		r.Finalize()
		return r, err
	}
	before := len(r.Findings)
	r.Add(baseline.Diff(base, s)...)
	r.AddStage("drift", stageStatus(len(r.Findings)-before),
		fmt.Sprintf("compared %d tools against baseline", len(s.Tools)))
	r.Finalize()
	return r, nil
}

func stageStatus(added int) findings.StageStatus {
	if added == 0 {
		return findings.StageNoFindings
	}
	return findings.StageCompleted
}
