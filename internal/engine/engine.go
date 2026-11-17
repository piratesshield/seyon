// Package engine orchestrates a scan: it connects to or ingests a target, runs
// the stages for the selected modes, and assembles a report. Phase 0 provides
// endpoint connection and enumeration; mode analyzers are layered on in later
// phases.
package engine

import (
	"context"
	"fmt"

	"seyon/internal/findings"
	"seyon/internal/mcp"
	"seyon/internal/report"
	"seyon/internal/source"
	"seyon/internal/transport"
)

// Connect builds an MCP client for a live endpoint. The returned client owns
// its transport; call Close when done.
//
// Safety note: a stdio endpoint spawns a process. In a full black-box scan the
// engine only does this inside the sandbox (Phase 3); Connect itself performs
// no isolation and is used directly only against trusted local targets such as
// the test lab.
func Connect(ctx context.Context, spec *source.EndpointSpec) (*mcp.Client, error) {
	switch spec.Scheme {
	case source.SchemeStdio:
		t, err := transport.SpawnStdio(ctx, spec.Command, spec.Args...)
		if err != nil {
			return nil, err
		}
		return mcp.NewClient(t), nil
	case source.SchemeHTTP:
		return mcp.NewClient(transport.NewHTTP(spec.URL)), nil
	default:
		return nil, fmt.Errorf("engine: unsupported endpoint scheme")
	}
}

// EnumerateReport connects to a live endpoint, enumerates its surface, and
// returns a report with the inventory and stage outcomes recorded. No detectors
// run yet in Phase 0, so the analyze stage reports no findings.
func EnumerateReport(ctx context.Context, version string, spec *source.EndpointSpec) (*report.Report, error) {
	r := report.New(version, spec.Raw, []findings.Mode{findings.ModeBlack})

	client, err := Connect(ctx, spec)
	if err != nil {
		r.AddStage("connect", findings.StageError, err.Error())
		r.Finalize()
		return r, err
	}
	defer func() { _ = client.Close() }()
	r.AddStage("connect", findings.StageCompleted, "")

	inv, err := client.Enumerate(ctx)
	if err != nil {
		r.AddStage("enumerate", findings.StageError, err.Error())
		r.Finalize()
		return r, err
	}
	r.Inventory = &report.InventorySummary{
		Server:    inv.Server.Name,
		Protocol:  inv.Protocol,
		Tools:     len(inv.Tools),
		Resources: len(inv.Resources),
		Prompts:   len(inv.Prompts),
		Complete:  inv.Complete,
	}
	status := findings.StageCompleted
	detail := ""
	if !inv.Complete {
		status = findings.StageCompleted
		detail = "enumeration incomplete: surface may be partial"
	}
	r.AddStage("enumerate", status, detail)

	// Phase 0 has no detectors; record the analyze stage honestly.
	r.AddStage("analyze", findings.StageNoFindings, "no detectors in this build")

	r.Finalize()
	return r, nil
}
