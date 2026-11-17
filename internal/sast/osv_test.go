package sast

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seyon/internal/findings"
)

// fakeOSV is an httptest server that mimics the two OSV endpoints Seyon uses.
// vulnsByCoord maps "ecosystem\x00name\x00version" to the OSV IDs affecting it;
// details maps an OSV ID to its advisory record.
type fakeOSV struct {
	vulnsByCoord map[string][]string
	details      map[string]osvVuln
	batchCalls   int
	lastQueries  []osvQuery
}

func (f *fakeOSV) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		f.batchCalls++
		var req osvBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.lastQueries = append(f.lastQueries, req.Queries...)
		var resp osvBatchResponse
		for _, q := range req.Queries {
			key := q.Package.Ecosystem + "\x00" + q.Package.Name + "\x00" + q.Version
			var vulns []struct {
				ID string `json:"id"`
			}
			for _, id := range f.vulnsByCoord[key] {
				vulns = append(vulns, struct {
					ID string `json:"id"`
				}{ID: id})
			}
			resp.Results = append(resp.Results, struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			}{Vulns: vulns})
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		v, ok := f.details[id]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	})
	return mux
}

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// vulnFinding returns the single D1 vulnerable-dependency finding whose target
// tool matches toolAtVer, or nil.
func vulnFinding(fs []findings.Finding, toolAtVer string) *findings.Finding {
	for i := range fs {
		f := fs[i]
		if f.RuleID == "D1.vulnerable-dependency" && f.Target.Tool == toolAtVer {
			return &fs[i]
		}
	}
	return nil
}

func sev(id, cve, severity, summary string) osvVuln {
	v := osvVuln{ID: id, Summary: summary}
	v.DatabaseSpecific.Severity = severity
	if cve != "" {
		v.Aliases = []string{cve}
	}
	return v
}

func TestOSVScanAcrossEcosystems(t *testing.T) {
	f := &fakeOSV{
		vulnsByCoord: map[string][]string{
			"Go\x00github.com/vuln/pkg\x001.0.0": {"OSV-GO-1"},
			"PyPI\x00requests\x002.0.0":          {"OSV-PY-1", "OSV-PY-2"},
			"npm\x00lodash\x004.17.21":           {"GHSA-test-lodash"},
			// flask and express resolve clean.
		},
		details: map[string]osvVuln{
			"OSV-GO-1":         sev("OSV-GO-1", "CVE-2099-1000", "HIGH", "Go pkg flaw"),
			"OSV-PY-1":         sev("OSV-PY-1", "", "MODERATE", "Requests minor issue"),
			"OSV-PY-2":         sev("OSV-PY-2", "CVE-2099-2000", "CRITICAL", "Requests RCE"),
			"GHSA-test-lodash": sev("GHSA-test-lodash", "CVE-2099-0001", "HIGH", "Lodash flaw"),
		},
	}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module testmod\n\ngo 1.22\n\nrequire github.com/vuln/pkg v1.0.0\n")
	writeFile(t, dir, "requirements.txt", "requests==2.0.0\nflask==2.1.0\n")
	writeFile(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.21","express":"4.18.0"}}`)

	a, err := NewAnalyzer(Options{OSV: true, OSVBaseURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("new analyzer: %v", err)
	}
	fs, err := a.AnalyzeDir(context.Background(), dir)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	// Exactly one finding per vulnerable coordinate; none for clean deps.
	var d1 int
	for _, x := range fs {
		if x.RuleID == "D1.vulnerable-dependency" {
			d1++
		}
	}
	if d1 != 3 {
		t.Fatalf("want 3 vulnerable-dependency findings, got %d: %+v", d1, fs)
	}
	if vulnFinding(fs, "express@4.18.0") != nil || vulnFinding(fs, "flask@2.1.0") != nil {
		t.Error("clean dependency reported as vulnerable")
	}

	// Go finding.
	if g := vulnFinding(fs, "github.com/vuln/pkg@1.0.0"); g == nil {
		t.Error("missing Go D1 finding")
	} else {
		if g.Target.Source != "go.mod" {
			t.Errorf("Go finding source = %q, want go.mod", g.Target.Source)
		}
		if g.Severity != findings.SeverityHigh {
			t.Errorf("Go finding severity = %q, want high", g.Severity)
		}
		if g.Confidence != findings.ConfidenceFirm {
			t.Errorf("Go finding confidence = %q, want firm", g.Confidence)
		}
		if !strings.Contains(g.Evidence.Note, "CVE-2099-1000") {
			t.Errorf("Go finding note missing CVE alias: %q", g.Evidence.Note)
		}
	}

	// PyPI finding folds two advisories and takes the max (critical) severity.
	if p := vulnFinding(fs, "requests@2.0.0"); p == nil {
		t.Error("missing PyPI D1 finding")
	} else {
		if p.Severity != findings.SeverityCritical {
			t.Errorf("PyPI finding severity = %q, want critical (max of folded advisories)", p.Severity)
		}
		if !strings.Contains(p.Evidence.Note, "CVE-2099-2000") || !strings.Contains(p.Evidence.Note, "OSV-PY-1") {
			t.Errorf("PyPI finding note should list both advisories: %q", p.Evidence.Note)
		}
		if !strings.Contains(strings.Join(p.References, " "), "https://osv.dev/vulnerability/OSV-PY-2") {
			t.Errorf("PyPI finding missing OSV reference link: %v", p.References)
		}
	}

	// npm finding.
	if n := vulnFinding(fs, "lodash@4.17.21"); n == nil {
		t.Error("missing npm D1 finding")
	} else if n.Target.Source != "package.json" {
		t.Errorf("npm finding source = %q, want package.json", n.Target.Source)
	}

	// Coordinates (and only coordinates) are what we sent: one batch, correct
	// ecosystem mapping, no clean-dep omissions.
	if f.batchCalls != 1 {
		t.Errorf("want a single batched querybatch call, got %d", f.batchCalls)
	}
	ecos := map[string]bool{}
	for _, q := range f.lastQueries {
		ecos[q.Package.Ecosystem] = true
	}
	for _, want := range []string{"Go", "PyPI", "npm"} {
		if !ecos[want] {
			t.Errorf("querybatch missing ecosystem %q (sent: %+v)", want, f.lastQueries)
		}
	}
}

func TestOSVFailureFallsBackToEmbedded(t *testing.T) {
	// A server that errors on querybatch forces the fallback path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	// lodash@4.17.20 is in the embedded advisory set, so the fallback must find it.
	writeFile(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.20"}}`)

	a, err := NewAnalyzer(Options{OSV: true, OSVBaseURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("new analyzer: %v", err)
	}
	fs, err := a.AnalyzeDir(context.Background(), dir)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	if vulnFinding(fs, "lodash@4.17.20") == nil {
		t.Error("fallback to embedded advisory set did not report the known lodash CVE")
	}
	var sawUnavailable bool
	for _, x := range fs {
		if x.RuleID == "D1.osv-unavailable" {
			sawUnavailable = true
			if x.Severity != findings.SeverityInfo {
				t.Errorf("osv-unavailable severity = %q, want info", x.Severity)
			}
		}
	}
	if !sawUnavailable {
		t.Error("expected an honest D1.osv-unavailable info finding when live OSV failed")
	}
}

func TestOSVDisabledMakesNoNetworkCalls(t *testing.T) {
	// If the analyzer is offline (default), a configured-but-unused server must
	// never be contacted.
	f := &fakeOSV{vulnsByCoord: map[string][]string{}, details: map[string]osvVuln{}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.20"}}`)

	a, err := NewAnalyzer(Options{}) // OSV off
	if err != nil {
		t.Fatalf("new analyzer: %v", err)
	}
	if _, err := a.AnalyzeDir(context.Background(), dir); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if f.batchCalls != 0 {
		t.Errorf("offline analyzer made %d OSV calls, want 0", f.batchCalls)
	}
}
