package engine

import (
	"context"
	"fmt"

	"seyon/internal/findings"
	"seyon/internal/report"
	"seyon/internal/sast"
	"seyon/internal/source"
)

// WhiteScan runs the white-box static analyzer over a resolved source tree.
// When osv is set, dependency checks query OSV.dev live instead of the embedded
// advisory set.
func WhiteScan(ctx context.Context, version string, resolved *source.Resolved, osv bool) (*report.Report, error) {
	r := report.New(version, resolved.Origin, []findings.Mode{findings.ModeWhite})
	if resolved.Kind != source.KindDir {
		err := fmt.Errorf("white-box scan needs a source directory, got %s", resolved.Kind)
		r.AddStage("ingest", findings.StageError, err.Error())
		r.Finalize()
		return r, err
	}

	a, err := sast.NewAnalyzer(sast.Options{OSV: osv})
	if err != nil {
		return nil, fmt.Errorf("white: init analyzer: %w", err)
	}
	fs, err := a.AnalyzeDir(ctx, resolved.Root)
	if err != nil {
		r.AddStage("sast", findings.StageError, err.Error())
		r.Add(fs...)
		r.Finalize()
		return r, err
	}
	r.Add(fs...)
	r.AddStage("sast", stageStatus(len(fs)), fmt.Sprintf("scanned %s", resolved.Origin))
	r.Finalize()
	return r, nil
}
