package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"seyon/internal/correlate"
	"seyon/internal/detect"
	"seyon/internal/findings"
	"seyon/internal/mcp"
	"seyon/internal/probe"
	"seyon/internal/report"
	"seyon/internal/sandbox"
	"seyon/internal/scope"
	"seyon/internal/source"
	"seyon/internal/surface"
	"seyon/internal/transport"
)

// BlackOptions controls black-box behavior. The zero value is a passive scan:
// connect, enumerate, and run the declared-surface detectors. Active probing is
// off unless Active is set AND a Scope authorizes the target.
type BlackOptions struct {
	Active bool
	Scope  *scope.Scope
	// RuleDirs are external rule-pack directories to load alongside the built-in
	// detectors for the passive surface analysis.
	RuleDirs []string
	// Headers are extra HTTP headers (e.g. Authorization) sent to an HTTP target,
	// so an authenticated MCP server can be enumerated with a token the operator
	// is authorized to use. Ignored for stdio targets.
	Headers http.Header
	// Toggles optionally disables individual scan stages. Nil = run everything.
	// Passed through from the web UI / CLI so operators can scope a scan to
	// what they actually need (e.g. "just TLS posture" or "no mutation fuzz").
	Toggles *Toggles
}

// Toggles is the per-stage on/off map. A nil field means "default" (on);
// a non-nil false means "explicitly disabled". This lets the web UI send
// only the flags the user changed without the server treating omitted fields
// as "off".
type Toggles struct {
	Surface      *bool `json:"surface,omitempty"`       // pattern rules + schema refs over declared tools/prompts/resources
	Instructions *bool `json:"instructions,omitempty"`  // scan server instructions from handshake
	Prompts      *bool `json:"prompts,omitempty"`       // fetch prompts/get bodies and scan
	Resources    *bool `json:"resources,omitempty"`     // fetch resources/read bodies and scan
	Readiness    *bool `json:"readiness,omitempty"`     // 20 operational-readiness heuristics
	Protocol     *bool `json:"protocol,omitempty"`      // P-class wire-protocol probes
	UnauthAudit  *bool `json:"unauth_audit,omitempty"`  // U-class deep unauth audit (TLS, headers, CORS, OAuth, JWKS, smuggling, ports, DNS, downgrade)
	ActiveProbe  *bool `json:"active_probe,omitempty"`  // active tool invocation with inert canaries
	MutationFuzz *bool `json:"mutation_fuzz,omitempty"` // parameter mutation fuzzing on tools
	LLM          *bool `json:"llm,omitempty"`           // optional LLM-based semantic classifier
	Correlate    *bool `json:"correlate,omitempty"`     // cross-mode correlation pass
}

// on reports whether a stage toggle is on. nil = default (true).
func (t *Toggles) on(b *bool) bool {
	if t == nil || b == nil {
		return true
	}
	return *b
}

// Per-stage accessors — return the toggle pointer or nil when Toggles itself
// is nil. All together so a reviewer can see the stage list at a glance.
func (t *Toggles) surface() *bool {
	if t == nil {
		return nil
	}
	return t.Surface
}
func (t *Toggles) instructions() *bool {
	if t == nil {
		return nil
	}
	return t.Instructions
}
func (t *Toggles) prompts() *bool {
	if t == nil {
		return nil
	}
	return t.Prompts
}
func (t *Toggles) resources() *bool {
	if t == nil {
		return nil
	}
	return t.Resources
}
func (t *Toggles) readiness() *bool {
	if t == nil {
		return nil
	}
	return t.Readiness
}
func (t *Toggles) protocol() *bool {
	if t == nil {
		return nil
	}
	return t.Protocol
}
func (t *Toggles) unauthAudit() *bool {
	if t == nil {
		return nil
	}
	return t.UnauthAudit
}
func (t *Toggles) activeProbe() *bool {
	if t == nil {
		return nil
	}
	return t.ActiveProbe
}
func (t *Toggles) mutationFuzz() *bool {
	if t == nil {
		return nil
	}
	return t.MutationFuzz
}
func (t *Toggles) llm() *bool {
	if t == nil {
		return nil
	}
	return t.LLM
}
func (t *Toggles) correlate() *bool {
	if t == nil {
		return nil
	}
	return t.Correlate
}

// BlackScan runs a black-box scan against a live endpoint. Passive analysis
// always runs. Active probing (tool invocation with inert canaries) runs only
// when authorized; otherwise the active-probe stage is recorded as skipped with
// the reason, so a report never hides that probing was declined.
func BlackScan(ctx context.Context, version string, spec *source.EndpointSpec, opts BlackOptions) (*report.Report, error) {
	r := report.New(version, spec.Raw, []findings.Mode{findings.ModeBlack})

	client, egressNote, dialMeta, err := connectForScan(ctx, spec, opts)
	if err != nil {
		// Handshake failed (auth-gated endpoint, DNS, refused, protocol
		// mismatch). We can't enumerate tools without a working session, but
		// the UNAUTH posture probes — P1 transport, P4 replay, P6 fail-open,
		// P7 rate-limit, P8 identity-spoofing — don't need a successful
		// handshake. They are safe read-only checks that still produce
		// meaningful findings against an auth-gated server. This is
		// equivalent to Cisco's `mcp-scanner protocol` subcommand.
		r.AddStage("connect", findings.StageError, err.Error())

		rf := reconFromError(err, spec.Raw)
		r.Add(rf...)
		r.AddStage("recon", stageStatus(len(rf)), "classified the dial failure")

		// Still run the wire-protocol probes if this is an HTTP target.
		// These findings tell the operator what posture the (possibly
		// auth-gated) endpoint has at the transport layer.
		runProtocolProbe(ctx, r, spec, opts)

		// Deep unauth audit: TLS, security headers, CORS, OAuth discovery,
		// server fingerprint, sensitive paths, info disclosure. These are the
		// checks an MCP security engineer runs when they have no credentials
		// but want everything the server leaks for free.
		runUnauthAudit(ctx, r, spec, opts)

		r.Finalize()
		// Return the raw error too so the web UI can show both the error
		// banner and the structured findings on the same page.
		return r, err
	}
	defer func() { _ = client.Close() }()
	r.AddStage("connect", findings.StageCompleted, joinNotes(egressNote, dialMeta.note))

	// Each stage checks its toggle; a disabled stage records StageSkipped so
	// the operator sees it was intentionally off, not silently absent.
	t := opts.Toggles
	if t.on(t.protocol()) {
		runProtocolProbe(ctx, r, spec, opts)
	} else {
		r.AddStage("protocol", findings.StageSkipped, "disabled by user")
	}
	if t.on(t.unauthAudit()) {
		runUnauthAudit(ctx, r, spec, opts)
	} else {
		r.AddStage("unauth-audit", findings.StageSkipped, "disabled by user")
	}

	inv, err := client.Enumerate(ctx)
	if err != nil {
		// Enumeration failed, but a black-box scan should still report what the
		// failure reveals (endpoint reachable, auth-gated, absent, erroring).
		r.AddStage("enumerate", findings.StageError, err.Error())
		rf := reconFromError(err, spec.Raw)
		r.Add(rf...)
		r.AddStage("recon", stageStatus(len(rf)), "classified the handshake response")
		r.Finalize()
		return r, nil
	}
	r.Inventory = &report.InventorySummary{
		Server:    inv.Server.Name,
		Protocol:  inv.Protocol,
		Transport: dialMeta.transport,
		Endpoint:  dialMeta.endpoint,
		Tools:     len(inv.Tools),
		Resources: len(inv.Resources),
		Prompts:   len(inv.Prompts),
		Complete:  inv.Complete,
	}
	detail := ""
	if !inv.Complete {
		detail = "enumeration incomplete: surface may be partial"
	}
	r.AddStage("enumerate", findings.StageCompleted, detail)

	// Passive: run the gray-box surface detectors over the live surface.
	a, err := detect.NewAnalyzer(opts.RuleDirs...)
	if err != nil {
		r.Finalize()
		return r, fmt.Errorf("black: load detectors: %w", err)
	}
	s := surface.FromInventory(inv, spec.Raw)
	if t.on(t.surface()) {
		before := len(r.Findings)
		r.Add(a.Surface(s)...)
		for _, tool := range inv.Tools {
			r.Add(a.Text(detect.TextToolDescription, tool.Name, spec.Raw, tool.Description)...)
		}
		r.AddStage("surface", stageStatus(len(r.Findings)-before),
			fmt.Sprintf("%d tools, %d prompts (declared surface)", len(inv.Tools), len(inv.Prompts)))
	} else {
		r.AddStage("surface", findings.StageSkipped, "disabled by user")
	}

	if t.on(t.readiness()) {
		readyBefore := len(r.Findings)
		r.Add(a.ReadinessOnTools(inv.Tools, spec.Raw)...)
		r.AddStage("readiness", stageStatus(len(r.Findings)-readyBefore),
			fmt.Sprintf("%d tool description(s) checked against 20 readiness rules", len(inv.Tools)))
	} else {
		r.AddStage("readiness", findings.StageSkipped, "disabled by user")
	}

	if t.on(t.instructions()) {
		if inv.Instructions != "" {
			instrBefore := len(r.Findings)
			r.Add(a.Text(detect.TextInstructions, inv.Server.Name, spec.Raw, inv.Instructions)...)
			r.AddStage("instructions", stageStatus(len(r.Findings)-instrBefore),
				fmt.Sprintf("%d chars", len(inv.Instructions)))
		} else {
			r.AddStage("instructions", findings.StageSkipped, "server did not advertise instructions")
		}
	} else {
		r.AddStage("instructions", findings.StageSkipped, "disabled by user")
	}

	if t.on(t.prompts()) {
		runPromptBodyScan(ctx, r, a, client, inv, spec.Raw)
	} else {
		r.AddStage("prompts", findings.StageSkipped, "disabled by user")
	}

	if t.on(t.resources()) {
		runResourceBodyScan(ctx, r, a, client, inv, spec.Raw)
	} else {
		r.AddStage("resources", findings.StageSkipped, "disabled by user")
	}

	if t.on(t.llm()) {
		runLLMSemantic(ctx, r, inv)
	} else {
		r.AddStage("llm", findings.StageSkipped, "disabled by user")
	}

	runActiveProbeGated(ctx, r, client, inv, spec, opts)

	if t.on(t.correlate()) {
		corr := correlate.Findings(r.Findings)
		r.Add(corr...)
		r.AddStage("correlate", stageStatus(len(corr)),
			fmt.Sprintf("%d cross-mode correlation(s)", len(corr)))
	} else {
		r.AddStage("correlate", findings.StageSkipped, "disabled by user")
	}

	r.Finalize()
	return r, nil
}

// runActiveProbeGated layers user toggles on top of the authorization gate.
// Each sub-stage (active probe, mutation fuzz) can be disabled independently;
// if active probing itself is turned off, mutation fuzz also skips because
// it depends on the same session.
func runActiveProbeGated(ctx context.Context, r *report.Report, client *mcp.Client, inv *mcp.Inventory, spec *source.EndpointSpec, opts BlackOptions) {
	t := opts.Toggles
	activeOn := t.on(t.activeProbe())
	fuzzOn := t.on(t.mutationFuzz())

	if !activeOn && !fuzzOn {
		r.AddStage("active-probe", findings.StageSkipped, "disabled by user")
		r.AddStage("mutation-fuzz", findings.StageSkipped, "disabled by user")
		return
	}

	switch {
	case !opts.Active:
		r.AddStage("active-probe", findings.StageSkipped,
			"active probing not requested (safe-by-default; pass --active with a scope file)")
		r.AddStage("mutation-fuzz", findings.StageSkipped, "requires active probing")
		return
	case opts.Scope == nil:
		r.AddStage("active-probe", findings.StageSkipped, "no scope file provided")
		r.AddStage("mutation-fuzz", findings.StageSkipped, "no scope file provided")
		return
	case !opts.Scope.Authorizes(spec.Raw):
		r.AddStage("active-probe", findings.StageSkipped,
			fmt.Sprintf("target %q is not authorized by the scope file", spec.Raw))
		r.AddStage("mutation-fuzz", findings.StageSkipped, "requires active probing")
		return
	}

	p := probe.New(opts.Scope.MaxCallsPerTool)
	if activeOn {
		before := len(r.Findings)
		res := p.ProbeAll(ctx, client, inv, spec.Raw)
		r.Add(res.Findings...)
		r.AddStage("active-probe", stageStatus(len(r.Findings)-before),
			fmt.Sprintf("%d inert tool call(s) across %d tool(s)", res.Calls, len(inv.Tools)))
	} else {
		r.AddStage("active-probe", findings.StageSkipped, "disabled by user")
	}

	if fuzzOn {
		fuzzBefore := len(r.Findings)
		fuzzRes := p.FuzzAll(ctx, client, inv, spec.Raw)
		r.Add(fuzzRes.Findings...)
		r.AddStage("mutation-fuzz", stageStatus(len(r.Findings)-fuzzBefore),
			fmt.Sprintf("%d mutation(s) across %d tool(s)", fuzzRes.Calls, len(inv.Tools)))
	} else {
		r.AddStage("mutation-fuzz", findings.StageSkipped, "disabled by user")
	}
}

// dialInfo carries what the dialer decided for the report inventory.
type dialInfo struct {
	transport string
	endpoint  string
	note      string
}

// connectForScan builds a client for the target.
//
// HTTP targets go through the mcp.Dial auto-detector: it tries Streamable HTTP,
// falls back to legacy SSE, probes common path suffixes when the exact URL
// fails, negotiates the MCP protocol version, and returns the Initialize
// result pre-populated so Enumerate() does not re-handshake.
//
// For a spawned stdio target under active probing, this applies the scope's
// egress policy via the sandbox and returns a note describing the isolation
// actually achieved. HTTP targets are not spawned, so egress isolation does not
// apply to them.
func connectForScan(ctx context.Context, spec *source.EndpointSpec, opts BlackOptions) (*mcp.Client, string, dialInfo, error) {
	// An HTTP target may need auth headers to get past a login wall.
	if spec.Scheme == source.SchemeHTTP {
		dialOpts := mcp.DialOptions{
			Headers:    opts.Headers,
			ProbePaths: probePathsFor(spec.URL),
		}
		res, err := mcp.Dial(ctx, spec.URL, dialOpts)
		if err != nil {
			return nil, "", dialInfo{}, err
		}
		res.Client.MarkInitialized(res.Initialize) // dialer already did the handshake; don't re-handshake in Enumerate
		note := ""
		if len(opts.Headers) > 0 {
			note = fmt.Sprintf("sending %d caller-supplied header(s)", len(opts.Headers))
		}
		return res.Client, note, dialInfo{
			transport: string(res.Kind),
			endpoint:  res.URL,
			note:      res.Note,
		}, nil
	}

	needSandbox := opts.Active && opts.Scope != nil && spec.Scheme == source.SchemeStdio && opts.Scope.EgressDenied()
	if !needSandbox {
		c, err := Connect(ctx, spec)
		if err != nil {
			return nil, "", dialInfo{}, err
		}
		info := dialInfo{transport: "stdio", endpoint: spec.Raw}
		if spec.Scheme == source.SchemeStdio && opts.Active {
			return c, "stdio target spawned without egress isolation (scope allows egress)", info, nil
		}
		return c, "", info, nil
	}

	plan := sandbox.Build(sandbox.Policy{DenyEgress: true}, spec.Command, spec.Args)
	cmd := exec.CommandContext(ctx, plan.Name, plan.Args...)
	t, err := transport.SpawnStdioCmd(cmd, spec.Command)
	if err != nil {
		return nil, "", dialInfo{}, err
	}
	note := "egress isolation: " + plan.Method
	if !plan.EgressIsolated {
		note = "WARNING — egress NOT isolated: " + plan.Method
	}
	return mcp.NewClient(t), note, dialInfo{transport: "stdio", endpoint: spec.Raw}, nil
}

// Prompt / resource scan budgets. Mirror Cisco's values so a single server
// cannot drown the scanner in multi-MB prompt bodies.
const (
	maxPromptsPerScan        = 100
	maxPromptBodyChars       = 100 * 1024
	maxResourceBodyChars     = 100 * 1024
	maxAggregateContentChars = 1024 * 1024
	contentReadTimeout       = 30 * time.Second
)

// resourceMimeAllowlist is the set of MIME types the scanner reads. Binary
// types (images, PDFs, archives) get a one-line skip note. The set is
// intentionally conservative — the goal is to analyze text the agent would
// consume, not every byte on the server.
var resourceMimeAllowlist = map[string]bool{
	"":                   true, // unknown, often plain text in practice
	"text/plain":         true,
	"text/html":          true,
	"text/markdown":      true,
	"text/csv":           true,
	"text/xml":           true,
	"application/json":   true,
	"application/xml":    true,
	"application/yaml":   true,
	"application/x-yaml": true,
}

// runPromptBodyScan calls prompts/get for each enumerated prompt with inert
// default-filler arguments, then runs the text analyzer on the rendered
// messages. Records a 'prompts' stage summarising coverage and errors.
func runPromptBodyScan(ctx context.Context, r *report.Report, a *detect.Analyzer, client *mcp.Client, inv *mcp.Inventory, origin string) {
	if len(inv.Prompts) == 0 {
		r.AddStage("prompts", findings.StageSkipped, "server exposed no prompts")
		return
	}
	before := len(r.Findings)
	accepted := 0
	fetched := 0
	errs := 0
	remaining := maxAggregateContentChars

	for _, p := range inv.Prompts {
		if accepted >= maxPromptsPerScan || remaining <= 0 {
			break
		}
		accepted++
		// Construct benign defaults for every declared argument. The scanner
		// is not trying to exercise the prompt's logic; it just wants to see
		// what text the server returns, which is often static boilerplate.
		args := map[string]string{}
		for _, arg := range p.Arguments {
			args[arg.Name] = "scan"
		}
		pctx, cancel := context.WithTimeout(ctx, contentReadTimeout)
		res, err := client.GetPrompt(pctx, p.Name, args)
		cancel()
		if err != nil {
			errs++
			continue
		}
		fetched++
		text := res.Text()
		if len(text) > maxPromptBodyChars {
			text = text[:maxPromptBodyChars]
		}
		if len(text) > remaining {
			text = text[:remaining]
		}
		remaining -= len(text)

		// Merge the list-time description with the body for one analysis pass.
		combined := p.Description
		if text != "" {
			if combined != "" {
				combined += "\n\n"
			}
			combined += text
		}
		r.Add(a.Text(detect.TextPromptMessages, p.Name, origin, combined)...)
	}
	detail := fmt.Sprintf("fetched %d/%d prompt(s)", fetched, len(inv.Prompts))
	if errs > 0 {
		detail += fmt.Sprintf(", %d error(s)", errs)
	}
	r.AddStage("prompts", stageStatus(len(r.Findings)-before), detail)
}

// runResourceBodyScan calls resources/read for each enumerated resource whose
// advertised MIME type is text-like, then runs the text analyzer on the body.
func runResourceBodyScan(ctx context.Context, r *report.Report, a *detect.Analyzer, client *mcp.Client, inv *mcp.Inventory, origin string) {
	if len(inv.Resources) == 0 {
		r.AddStage("resources", findings.StageSkipped, "server exposed no resources")
		return
	}
	before := len(r.Findings)
	fetched := 0
	skipped := 0
	errs := 0
	remaining := maxAggregateContentChars

	for _, res := range inv.Resources {
		if remaining <= 0 {
			break
		}
		mime := strings.ToLower(strings.TrimSpace(res.MIMEType))
		// Strip ;charset= and similar
		if i := strings.Index(mime, ";"); i >= 0 {
			mime = strings.TrimSpace(mime[:i])
		}
		if !resourceMimeAllowlist[mime] {
			skipped++
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, contentReadTimeout)
		body, err := client.ReadResource(rctx, res.URI)
		cancel()
		if err != nil {
			errs++
			continue
		}
		text, _, _ := body.TextWithMime(maxResourceBodyChars)
		if text == "" {
			skipped++
			continue
		}
		if len(text) > remaining {
			text = text[:remaining]
		}
		remaining -= len(text)
		fetched++
		// Merge name + description + body for one pass.
		var combined string
		if res.Name != "" {
			combined = res.Name + "\n"
		}
		if res.Description != "" {
			combined += res.Description + "\n"
		}
		combined += text
		r.Add(a.Text(detect.TextResource, res.URI, origin, combined)...)
	}
	detail := fmt.Sprintf("read %d/%d resource(s)", fetched, len(inv.Resources))
	if skipped > 0 {
		detail += fmt.Sprintf(", %d skipped (binary or empty)", skipped)
	}
	if errs > 0 {
		detail += fmt.Sprintf(", %d error(s)", errs)
	}
	r.AddStage("resources", stageStatus(len(r.Findings)-before), detail)
}

// runLLMSemantic runs the optional LLM-backed classifier over every scannable
// text block. The analyzer is OFF unless SEYON_LLM_API_KEY is set. Errors from
// the LLM are logged into the stage detail, not failed, so a rate-limited or
// 500-ing provider never blocks the rest of the scan.
func runLLMSemantic(ctx context.Context, r *report.Report, inv *mcp.Inventory) {
	llm := detect.LLMAnalyzerFromEnv()
	if llm == nil {
		r.AddStage("llm", findings.StageSkipped, "SEYON_LLM_API_KEY not set — analyzer disabled")
		return
	}
	before := len(r.Findings)
	errors := 0
	calls := 0
	lctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	submit := func(kind detect.TextKind, name, text string) {
		if text == "" {
			return
		}
		calls++
		got, err := llm.Analyze(lctx, kind, name, "", text)
		if err != nil {
			errors++
			return
		}
		r.Add(got...)
	}
	for _, t := range inv.Tools {
		submit(detect.TextToolDescription, t.Name, t.Description)
	}
	if inv.Instructions != "" {
		submit(detect.TextInstructions, inv.Server.Name, inv.Instructions)
	}
	detail := fmt.Sprintf("%d LLM call(s)", calls)
	if errors > 0 {
		detail += fmt.Sprintf(", %d error(s)", errors)
	}
	r.AddStage("llm", stageStatus(len(r.Findings)-before), detail)
}

// runProtocolProbe runs the wire-protocol checks for HTTP targets. stdio
// targets skip the stage — the checks don't apply to a spawned process.
func runProtocolProbe(ctx context.Context, r *report.Report, spec *source.EndpointSpec, opts BlackOptions) {
	if spec.Scheme != source.SchemeHTTP {
		r.AddStage("protocol", findings.StageSkipped, "stdio target: wire-protocol checks are HTTP-only")
		return
	}
	before := len(r.Findings)
	p := probe.NewProtocol(opts.Headers)
	pctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	r.Add(p.Run(pctx, spec.URL)...)
	r.AddStage("protocol", stageStatus(len(r.Findings)-before),
		"8 safe wire-protocol checks (transport, auth, signing, replay, integrity, fail-open, rate-limit, spoofed identity)")
}

// runUnauthAudit runs the deep unauthenticated posture audit: TLS stack,
// HTTP security headers, CORS, WWW-Authenticate challenge analysis, server
// fingerprint, OAuth/OIDC discovery, sensitive-path disclosure, and error-
// body info leaks. All checks are safe and read-only. HTTP-only.
//
// Runs on BOTH the posture path (handshake failed) AND the full-scan path,
// because the TLS / headers / CORS / OAuth signals are meaningful whether or
// not the operator has a working token.
func runUnauthAudit(ctx context.Context, r *report.Report, spec *source.EndpointSpec, opts BlackOptions) {
	if spec.Scheme != source.SchemeHTTP {
		r.AddStage("unauth-audit", findings.StageSkipped, "stdio target: unauth checks are HTTP-only")
		return
	}
	before := len(r.Findings)
	u := probe.NewUnauth(opts.Headers)
	uctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r.Add(u.Run(uctx, spec.URL)...)
	r.AddStage("unauth-audit", stageStatus(len(r.Findings)-before),
		"TLS, security headers, CORS, auth challenge, OAuth discovery, server fingerprint, sensitive paths, error-body info disclosure")
}

// probePathsFor decides whether and how to probe alternate paths on the host.
// Probing is enabled when the URL's path is empty, "/", or one of the common
// MCP conventions; a user who typed a specific application path (e.g.
// "/api/v2/mcp") probably knows where their endpoint lives, so we don't poke
// unrelated paths on their host.
func probePathsFor(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	path := strings.TrimRight(u.Path, "/")
	switch path {
	case "", "/mcp", "/sse", "/messages", "/rpc":
		return mcp.DefaultProbePaths
	}
	return nil
}

// joinNotes concatenates two non-empty notes with a separator; either may be
// empty.
func joinNotes(a, b string) string {
	switch {
	case a == "" && b == "":
		return ""
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + " · " + b
}
