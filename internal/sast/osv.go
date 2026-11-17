package sast

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"seyon/internal/findings"
)

// defaultOSVBaseURL is the public OSV.dev API root. OSV (https://osv.dev) is an
// open, read-only vulnerability database maintained by Google/OpenSSF.
const defaultOSVBaseURL = "https://api.osv.dev"

// osvMaxBatch is OSV's documented cap on queries per querybatch request.
const osvMaxBatch = 1000

// osvEcosystem maps Seyon's internal ecosystem codes to OSV ecosystem names.
// An unknown code returns "" and is skipped.
func osvEcosystem(eco string) string {
	switch eco {
	case "go":
		return "Go"
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	default:
		return ""
	}
}

// osvClient queries the OSV.dev API for known vulnerabilities affecting
// specific package versions. It transmits only package coordinates
// (ecosystem, name, version) — never source code, file contents, or paths.
type osvClient struct {
	baseURL string
	http    *http.Client
}

// newOSVClient builds a client. An empty baseURL uses the public OSV endpoint;
// a nil http.Client gets a default with a bounded timeout. Both are overridable
// so tests can point at an httptest.Server.
func newOSVClient(baseURL string, hc *http.Client) *osvClient {
	if baseURL == "" {
		baseURL = defaultOSVBaseURL
	}
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	return &osvClient{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

// --- OSV request/response shapes (only the fields Seyon consumes) ---

type osvPackageRef struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQuery struct {
	Version string        `json:"version"`
	Package osvPackageRef `json:"package"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

type osvVuln struct {
	ID               string   `json:"id"`
	Summary          string   `json:"summary"`
	Details          string   `json:"details"`
	Aliases          []string `json:"aliases"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

// scan queries OSV for every coordinate and returns one D1 finding per
// vulnerable (manifest file, package@version). Coordinates are de-duplicated
// before querying, so the same dependency declared in several files costs one
// query. A transport or protocol error is returned so the caller can report the
// degradation honestly rather than silently pretending a clean result.
func (c *osvClient) scan(ctx context.Context, coords []depCoord) ([]findings.Finding, error) {
	if len(coords) == 0 {
		return nil, nil
	}

	// Build de-duplicated OSV queries, remembering which query index each
	// distinct (ecosystem,name,version) maps to.
	type qkey struct{ eco, name, ver string }
	index := map[qkey]int{}
	var queries []osvQuery
	for _, co := range coords {
		oe := osvEcosystem(co.eco)
		if oe == "" {
			continue
		}
		k := qkey{oe, co.name, co.ver}
		if _, ok := index[k]; ok {
			continue
		}
		index[k] = len(queries)
		queries = append(queries, osvQuery{Version: co.ver, Package: osvPackageRef{Name: co.name, Ecosystem: oe}})
	}
	if len(queries) == 0 {
		return nil, nil
	}

	idsPerQuery, err := c.queryBatch(ctx, queries)
	if err != nil {
		return nil, err
	}

	// Fetch details once per distinct vuln ID; group vulns by query key.
	details := map[string]osvVuln{}
	vulnsByKey := map[qkey][]osvVuln{}
	for k, qi := range index {
		for _, id := range idsPerQuery[qi] {
			v, ok := details[id]
			if !ok {
				fetched, ferr := c.vuln(ctx, id)
				if ferr != nil {
					if ctx.Err() != nil {
						return nil, ferr // honor cancellation/timeout
					}
					fetched = osvVuln{ID: id} // detail unavailable; still report the ID
				}
				details[id] = fetched
				v = fetched
			}
			vulnsByKey[k] = append(vulnsByKey[k], v)
		}
	}

	// Emit one finding per coord that has at least one vuln.
	var out []findings.Finding
	for _, co := range coords {
		oe := osvEcosystem(co.eco)
		if oe == "" {
			continue
		}
		vulns := vulnsByKey[qkey{oe, co.name, co.ver}]
		if len(vulns) == 0 {
			continue
		}
		out = append(out, osvFinding(co, vulns))
	}
	return out, nil
}

// queryBatch runs one or more querybatch requests (chunked at osvMaxBatch) and
// returns, per query, the list of vuln IDs affecting it.
func (c *osvClient) queryBatch(ctx context.Context, queries []osvQuery) ([][]string, error) {
	out := make([][]string, 0, len(queries))
	for start := 0; start < len(queries); start += osvMaxBatch {
		end := start + osvMaxBatch
		if end > len(queries) {
			end = len(queries)
		}
		body, err := json.Marshal(osvBatchRequest{Queries: queries[start:end]})
		if err != nil {
			return nil, err
		}
		var resp osvBatchResponse
		if err := c.post(ctx, "/v1/querybatch", body, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) != end-start {
			return nil, fmt.Errorf("osv: querybatch returned %d results for %d queries", len(resp.Results), end-start)
		}
		for _, r := range resp.Results {
			ids := make([]string, 0, len(r.Vulns))
			for _, v := range r.Vulns {
				ids = append(ids, v.ID)
			}
			out = append(out, ids)
		}
	}
	return out, nil
}

// vuln fetches the full advisory record for one OSV ID.
func (c *osvClient) vuln(ctx context.Context, id string) (osvVuln, error) {
	var v osvVuln
	err := c.get(ctx, "/v1/vulns/"+url.PathEscape(id), &v)
	return v, err
}

func (c *osvClient) post(ctx context.Context, path string, body []byte, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return c.do(req, dst)
}

func (c *osvClient) get(ctx context.Context, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	return c.do(req, dst)
}

func (c *osvClient) do(req *http.Request, dst any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("osv %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	// Bound the response body so a hostile or broken endpoint cannot exhaust memory.
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(dst)
}

// osvFinding builds the D1 finding for one vulnerable coordinate, folding every
// advisory affecting it into a single finding at the maximum severity.
func osvFinding(co depCoord, vulns []osvVuln) findings.Finding {
	sev := findings.SeverityInfo
	var labels, refs []string
	summary := ""
	for _, v := range vulns {
		sev = maxSeverity(sev, osvSeverity(v))
		labels = append(labels, vulnLabel(v))
		if v.ID != "" {
			refs = append(refs, "https://osv.dev/vulnerability/"+v.ID)
		}
		if summary == "" {
			summary = firstLine(v.Summary)
			if summary == "" {
				summary = firstLine(v.Details)
			}
		}
	}
	refs = append(refs, "supply-chain")

	note := fmt.Sprintf("%d known OSV advisory(ies): %s", len(vulns), strings.Join(labels, ", "))
	if summary != "" {
		note += " — " + summary
	}

	f := findings.Finding{
		RuleID:      "D1.vulnerable-dependency",
		Class:       "D1",
		Title:       "Dependency has a known vulnerability",
		Severity:    sev,
		Confidence:  findings.ConfidenceFirm,
		Modes:       []findings.Mode{findings.ModeWhite},
		Target:      findings.Target{Source: co.rel, Tool: co.name + "@" + co.ver},
		Evidence:    findings.Evidence{Note: note},
		References:  refs,
		Remediation: "Upgrade " + co.name + " to a version not affected by the listed OSV advisories.",
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return f
}

// osvUnavailableFinding records, honestly, that a requested live OSV lookup
// failed and the scan fell back to the embedded advisory set — so a thin
// dependency result is never mistaken for a clean one.
func osvUnavailableFinding(err error) findings.Finding {
	f := findings.Finding{
		RuleID:      "D1.osv-unavailable",
		Class:       "D1",
		Title:       "Live OSV lookup unavailable; used embedded advisories",
		Severity:    findings.SeverityInfo,
		Confidence:  findings.ConfidenceTentative,
		Modes:       []findings.Mode{findings.ModeWhite},
		Target:      findings.Target{Source: "dependencies"},
		Evidence:    findings.Evidence{Note: "OSV query failed: " + err.Error() + "; dependency results may be incomplete."},
		References:  []string{"supply-chain"},
		Remediation: "Re-run with network access to OSV.dev, or treat dependency coverage as partial.",
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return f
}

// osvSeverity maps an OSV advisory to a Seyon severity. It prefers the
// database-specific label (present on GHSA entries); absent that it falls back
// to "high" when CVSS vectors are present but unparsed, so a scored advisory is
// never under-reported as low.
func osvSeverity(v osvVuln) findings.Severity {
	switch strings.ToUpper(v.DatabaseSpecific.Severity) {
	case "CRITICAL":
		return findings.SeverityCritical
	case "HIGH":
		return findings.SeverityHigh
	case "MODERATE", "MEDIUM":
		return findings.SeverityMedium
	case "LOW":
		return findings.SeverityLow
	}
	// No database-specific label. CVSS vectors (v.Severity) may be present but
	// are not parsed into a base score here; treat a scored-but-unlabeled
	// advisory conservatively as high rather than under-reporting it.
	return findings.SeverityHigh
}

// vulnLabel renders a human-facing advisory label, preferring a CVE alias.
func vulnLabel(v osvVuln) string {
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			if v.ID != "" && v.ID != a {
				return a + " (" + v.ID + ")"
			}
			return a
		}
	}
	return v.ID
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	const max = 160
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "…"
	}
	return s
}

func maxSeverity(a, b findings.Severity) findings.Severity {
	if sevRank(a) >= sevRank(b) {
		return a
	}
	return b
}

func sevRank(s findings.Severity) int {
	switch s {
	case findings.SeverityCritical:
		return 5
	case findings.SeverityHigh:
		return 4
	case findings.SeverityMedium:
		return 3
	case findings.SeverityLow:
		return 2
	case findings.SeverityInfo:
		return 1
	}
	return 0
}
