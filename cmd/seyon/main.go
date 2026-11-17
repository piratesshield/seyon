// Command seyon is the Seyon MCP security scanner CLI.
//
// Seyon scans MCP servers from three vantage points — black-box (live
// enumeration, surface detectors, and authorized inert-canary probing),
// gray-box (config and surface-snapshot checks, drift detection), and white-box
// (static source analysis) — correlates findings across those modes, and
// reports as console, JSON, or SARIF. Active probing is safe-by-default: off
// unless a scope file authorizes the exact target.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"seyon/internal/baseline"
	"seyon/internal/discover"
	"seyon/internal/engine"
	"seyon/internal/report"
	"seyon/internal/scope"
	"seyon/internal/source"
	"seyon/internal/surface"
)

// headerList collects repeated --header flags ("Key: Value").
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

// parseHeaders turns "Key: Value" strings into an http.Header. A missing colon
// is an error, so a malformed flag fails loudly rather than being ignored.
func parseHeaders(items []string) (http.Header, error) {
	if len(items) == 0 {
		return nil, nil
	}
	hdr := http.Header{}
	for _, item := range items {
		k, v, ok := strings.Cut(item, ":")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("bad --header %q (want \"Key: Value\")", item)
		}
		hdr.Add(k, strings.TrimSpace(v))
	}
	return hdr, nil
}

var version = "2.0.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	switch os.Args[1] {
	case "enumerate":
		os.Exit(cmdEnumerate(ctx, os.Args[2:]))
	case "scan":
		os.Exit(cmdScan(ctx, os.Args[2:]))
	case "baseline":
		os.Exit(cmdBaseline(ctx, os.Args[2:]))
	case "diff":
		os.Exit(cmdDiff(ctx, os.Args[2:]))
	case "discover":
		os.Exit(cmdDiscover(ctx, os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("seyon", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "seyon: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `seyon `+version+` — MCP security scanner

usage:
  seyon enumerate <endpoint>                 list a server's tools/resources/prompts
  seyon scan --mode black <endpoint>         enumerate + surface-check a live server
  seyon scan --mode black --active --scope F <endpoint>
                                             also actively probe (authorized targets only)
  seyon scan --mode gray  <input>            analyze a config or surface snapshot
  seyon scan --mode white <dir|.zip|repo-url>   static source analysis of a server
  seyon scan --mode all   <dir|.zip|repo-url>   white + gray (discovered configs) + correlation
  seyon baseline -o FILE <surface-input>     pin a trusted surface snapshot
  seyon diff [--out F] <baseline> <input>    detect drift against a baseline
  seyon discover                             find MCP configs across installed IDEs
  seyon discover --scan                      discover + gray-scan all found configs
  seyon version

Flags must come before positional paths (e.g. 'baseline -o base.json surface.json').

endpoints (black):
  stdio:<command> [args...] | http(s)://host/path

active probing (black): safe-by-default and OFF unless BOTH are given:
  --active             opt in to invoking tools with inert canaries
  --scope FILE         a scope file that sets allow_active:true and lists the target
  Spawned stdio targets run with egress denied by default (see scope deny_egress).

gray / baseline / diff inputs (choose one):
  <path>                 a local mcp.json or surface-snapshot file
  --stdin                read the input from standard input
  --repo URL --config P  fetch file P from a Git repo (optional --ref)

white inputs (choose one):
  <dir>                  a local source directory
  <archive.zip>          a zipped source tree
  --repo URL             clone a Git repo (optional --ref)

authenticated black-box: --header "Authorization: Bearer <token>"   (repeatable)
  Sends the header(s) so an auth-gated MCP server can be enumerated. Use only
  with a token you are authorized to use; it does not bypass authentication.

rule packs (gray/black): --rules DIR   load extra *.yaml rule packs alongside built-ins

dependency vulnerabilities (white/all): --osv   query OSV.dev live instead of the
  small embedded advisory set. Opt-in: it sends package coordinates (ecosystem,
  name, version) to OSV.dev — never your source. If the lookup fails it falls
  back to the embedded set and says so. Default (off) is fully offline.

output (scan): --out console|json|sarif|html   (default console)
`)
}

func cmdEnumerate(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("enumerate", flag.ExitOnError)
	timeout := fs.Duration("timeout", 30*time.Second, "overall deadline")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "seyon enumerate: need exactly one endpoint")
		return 2
	}
	spec, err := source.ParseEndpoint(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "seyon:", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	r, err := engine.EnumerateReport(ctx, version, spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seyon: enumerate:", err)
		return 1
	}
	if err := report.WriteConsole(os.Stdout, r); err != nil {
		fmt.Fprintln(os.Stderr, "seyon: write report:", err)
		return 1
	}
	return 0
}

// grayInput holds the shared gray-box ingestion flags.
type grayInput struct {
	stdin  *bool
	repo   *string
	ref    *string
	config *string
}

func addGrayInputFlags(fs *flag.FlagSet) grayInput {
	return grayInput{
		stdin:  fs.Bool("stdin", false, "read input from standard input"),
		repo:   fs.String("repo", "", "fetch input from a Git repository URL"),
		ref:    fs.String("ref", "", "git ref (branch/tag) to fetch"),
		config: fs.String("config", "", "repo-relative path of the file to read (with --repo)"),
	}
}

// load reads the gray-box input using the first positional arg as the file
// path when no other source is selected.
func (g grayInput) load(ctx context.Context, fs *flag.FlagSet) ([]byte, string, func(), error) {
	path := ""
	if fs.NArg() >= 1 {
		path = fs.Arg(0)
	}
	return g.loadFrom(ctx, path)
}

// loadFrom reads the gray-box input bytes from the chosen source (--repo,
// --stdin, or the given file path) and returns them with an origin label and a
// cleanup function.
func (g grayInput) loadFrom(ctx context.Context, path string) ([]byte, string, func(), error) {
	noop := func() {}
	switch {
	case *g.repo != "":
		if *g.config == "" {
			return nil, "", noop, fmt.Errorf("--repo requires --config <path-in-repo>")
		}
		resolved, cleanup, err := source.GitClone(ctx, *g.repo, *g.ref)
		if err != nil {
			return nil, "", noop, err
		}
		data, err := source.ReadRepoFile(resolved, *g.config)
		if err != nil {
			cleanup()
			return nil, "", noop, err
		}
		return data, resolved.Origin + "/" + *g.config, cleanup, nil
	case *g.stdin:
		data, err := io.ReadAll(os.Stdin)
		return data, "stdin", noop, err
	case path != "":
		if _, err := source.Local(path); err != nil {
			return nil, "", noop, err
		}
		data, err := os.ReadFile(path)
		return data, "local:" + path, noop, err
	default:
		return nil, "", noop, fmt.Errorf("no input: give a path, --stdin, or --repo/--config")
	}
}

func cmdScan(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	mode := fs.String("mode", "black", "scanning mode: black|gray|white")
	out := fs.String("out", "console", "report format: console|json|sarif")
	timeout := fs.Duration("timeout", 30*time.Second, "overall deadline")
	active := fs.Bool("active", false, "enable active probing (requires --scope)")
	scopeFile := fs.String("scope", "", "scope file authorizing active probing")
	rulesDir := fs.String("rules", "", "directory of external rule packs (*.yaml) to load (gray/black)")
	osv := fs.Bool("osv", false, "query OSV.dev for live dependency vulnerabilities (white/all; sends package coordinates, not code)")
	var headers headerList
	fs.Var(&headers, "header", "extra HTTP header 'Key: Value' for an HTTP black-box target (repeatable)")
	gi := addGrayInputFlags(fs)
	_ = fs.Parse(args)

	hdr, herr := parseHeaders(headers)
	if herr != nil {
		fmt.Fprintln(os.Stderr, "seyon:", herr)
		return 2
	}

	var ruleDirs []string
	if *rulesDir != "" {
		ruleDirs = []string{*rulesDir}
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	var (
		r   *report.Report
		err error
	)
	switch *mode {
	case "black":
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "seyon scan --mode black: need exactly one endpoint")
			return 2
		}
		spec, perr := source.ParseEndpoint(fs.Arg(0))
		if perr != nil {
			fmt.Fprintln(os.Stderr, "seyon:", perr)
			return 2
		}
		opts, oerr := blackOptions(*active, *scopeFile)
		if oerr != nil {
			fmt.Fprintln(os.Stderr, "seyon:", oerr)
			return 2
		}
		opts.RuleDirs = ruleDirs
		opts.Headers = hdr
		r, err = engine.BlackScan(ctx, version, spec, opts)
	case "gray":
		if fs.NArg() > 1 {
			fmt.Fprintln(os.Stderr, "seyon scan --mode gray: unexpected extra arguments; put flags before the input path")
			return 2
		}
		data, origin, cleanup, lerr := gi.load(ctx, fs)
		if lerr != nil {
			fmt.Fprintln(os.Stderr, "seyon:", lerr)
			return 2
		}
		defer cleanup()
		r, err = engine.GrayScanWithRules(version, data, origin, ruleDirs)
	case "white":
		if fs.NArg() > 1 {
			fmt.Fprintln(os.Stderr, "seyon scan --mode white: unexpected extra arguments; put flags before the path")
			return 2
		}
		resolved, cleanup, rerr := resolveWhiteSource(ctx, gi, fs)
		if rerr != nil {
			fmt.Fprintln(os.Stderr, "seyon:", rerr)
			return 2
		}
		defer cleanup()
		r, err = engine.WhiteScan(ctx, version, resolved, *osv)
	case "all":
		if fs.NArg() > 1 {
			fmt.Fprintln(os.Stderr, "seyon scan --mode all: unexpected extra arguments; put flags before the path")
			return 2
		}
		resolved, cleanup, rerr := resolveWhiteSource(ctx, gi, fs)
		if rerr != nil {
			fmt.Fprintln(os.Stderr, "seyon:", rerr)
			return 2
		}
		defer cleanup()
		r, err = engine.CombinedScan(ctx, version, resolved, ruleDirs, *osv)
	default:
		fmt.Fprintf(os.Stderr, "seyon: mode %q is not implemented (black|gray|white|all)\n", *mode)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "seyon: scan:", err)
		// Still emit the report: it records the failed stage honestly.
	}
	if werr := writeReport(*out, r); werr != nil {
		fmt.Fprintln(os.Stderr, "seyon:", werr)
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

func cmdBaseline(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("baseline", flag.ExitOnError)
	outFile := fs.String("o", "", "output baseline file (default stdout)")
	gi := addGrayInputFlags(fs)
	_ = fs.Parse(args)

	if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "seyon baseline: unexpected extra arguments; put flags (e.g. -o) before the input path")
		return 2
	}
	data, origin, cleanup, err := gi.load(ctx, fs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seyon:", err)
		return 2
	}
	defer cleanup()

	s, err := surface.Parse(data, origin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seyon: baseline:", err)
		return 1
	}
	b := baseline.Compute(s)

	w := os.Stdout
	if *outFile != "" {
		f, cerr := os.Create(*outFile)
		if cerr != nil {
			fmt.Fprintln(os.Stderr, "seyon:", cerr)
			return 1
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	if err := baseline.Save(w, b); err != nil {
		fmt.Fprintln(os.Stderr, "seyon:", err)
		return 1
	}
	return 0
}

func cmdDiff(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	out := fs.String("out", "console", "report format: console|json|sarif")
	gi := addGrayInputFlags(fs)
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "seyon diff: need a baseline file (plus a surface input)")
		return 2
	}
	if fs.NArg() > 2 {
		fmt.Fprintln(os.Stderr, "seyon diff: unexpected extra arguments; put flags before the baseline and input paths")
		return 2
	}
	baseFile := fs.Arg(0)
	bf, err := os.Open(baseFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seyon:", err)
		return 2
	}
	defer func() { _ = bf.Close() }()
	base, err := baseline.Load(bf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seyon:", err)
		return 1
	}

	// The surface input is the second positional arg, or --stdin / --repo.
	surfaceArg := ""
	if fs.NArg() >= 2 {
		surfaceArg = fs.Arg(1)
	}
	data, origin, cleanup, err := gi.loadFrom(ctx, surfaceArg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seyon:", err)
		return 2
	}
	defer cleanup()

	r, err := engine.DriftScan(version, base, data, origin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seyon: diff:", err)
	}
	if werr := writeReport(*out, r); werr != nil {
		fmt.Fprintln(os.Stderr, "seyon:", werr)
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

func cmdDiscover(_ context.Context, args []string) int {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	doScan := fs.Bool("scan", false, "gray-scan all discovered configs")
	out := fs.String("out", "console", "report format: console|json|sarif")
	rulesDir := fs.String("rules", "", "directory of external rule packs")
	_ = fs.Parse(args)

	configs := discover.FindAll()
	if len(configs) == 0 {
		fmt.Fprintln(os.Stderr, "seyon discover: no MCP configurations found on this host")
		return 0
	}

	fmt.Fprintf(os.Stderr, "seyon discover: found %d MCP configuration(s):\n", len(configs))
	for _, c := range configs {
		fmt.Fprintf(os.Stderr, "  %-24s %s\n", c.IDE, c.Path)
	}

	if !*doScan {
		return 0
	}

	var ruleDirs []string
	if *rulesDir != "" {
		ruleDirs = []string{*rulesDir}
	}

	fmt.Fprintln(os.Stderr, "\nscanning discovered configs...")
	var exitCode int
	for _, c := range configs {
		data, err := os.ReadFile(c.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s: %v\n", c.Path, err)
			continue
		}
		r, serr := engine.GrayScanWithRules(version, data, c.IDE+":"+c.Path, ruleDirs)
		if serr != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", c.IDE, serr)
			continue
		}
		if r != nil && len(r.Findings) > 0 {
			if werr := writeReport(*out, r); werr != nil {
				fmt.Fprintln(os.Stderr, "seyon:", werr)
				return 1
			}
		}
	}
	return exitCode
}

// blackOptions builds black-box options, enforcing the safe-by-default gate:
// active probing requires a scope file that itself authorizes it.
func blackOptions(active bool, scopeFile string) (engine.BlackOptions, error) {
	if !active {
		if scopeFile != "" {
			return engine.BlackOptions{}, fmt.Errorf("--scope was given without --active; refusing to probe")
		}
		return engine.BlackOptions{}, nil
	}
	if scopeFile == "" {
		return engine.BlackOptions{}, fmt.Errorf("--active requires --scope FILE authorizing the target")
	}
	data, err := os.ReadFile(scopeFile)
	if err != nil {
		return engine.BlackOptions{}, fmt.Errorf("read scope file: %w", err)
	}
	sc, err := scope.Parse(data)
	if err != nil {
		return engine.BlackOptions{}, err
	}
	return engine.BlackOptions{Active: true, Scope: sc}, nil
}

// resolveWhiteSource resolves a white-box source tree from --repo, a repo URL
// or .zip given positionally, or a local directory path.
func resolveWhiteSource(ctx context.Context, gi grayInput, fs *flag.FlagSet) (*source.Resolved, func(), error) {
	noop := func() {}
	switch {
	case *gi.repo != "":
		return source.GitClone(ctx, *gi.repo, *gi.ref)
	case fs.NArg() == 1:
		path := fs.Arg(0)
		// A positional git URL is cloned, not treated as a local path — so
		// `scan --mode white https://github.com/org/repo` just works.
		if looksLikeRepoURL(path) {
			return source.GitClone(ctx, path, *gi.ref)
		}
		if strings.HasSuffix(strings.ToLower(path), ".zip") {
			return source.Unzip(path)
		}
		resolved, err := source.Local(path)
		if err != nil {
			return nil, noop, err
		}
		return resolved, noop, nil
	default:
		return nil, noop, fmt.Errorf("white-box scan needs a directory path, a repo URL, a .zip, or --repo")
	}
}

// looksLikeRepoURL reports whether s is a git repository URL rather than a local
// path, so it should be cloned.
func looksLikeRepoURL(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") ||
		strings.HasPrefix(s, "git@") || strings.HasPrefix(s, "ssh://") ||
		strings.HasSuffix(s, ".git")
}

func writeReport(format string, r *report.Report) error {
	switch format {
	case "json":
		return report.WriteJSON(os.Stdout, r)
	case "sarif":
		return report.WriteSARIF(os.Stdout, r)
	case "html":
		return report.WriteHTML(os.Stdout, r)
	case "console":
		return report.WriteConsole(os.Stdout, r)
	default:
		return fmt.Errorf("unknown output %q (console|json|sarif|html)", format)
	}
}
