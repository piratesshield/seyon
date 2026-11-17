package sast

import (
	"embed"
	"encoding/json"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"seyon/internal/findings"
)

//go:embed advisories.yaml
var advisoryFS embed.FS

// advisory is one known-vulnerable package version. Matching is exact on
// (ecosystem, name, version) for now; a live OSV client replaces this later.
type advisory struct {
	Ecosystem string `yaml:"ecosystem"` // go | npm | pypi
	Name      string `yaml:"name"`
	Version   string `yaml:"version"`
	ID        string `yaml:"id"`
	Severity  string `yaml:"severity"`
	Summary   string `yaml:"summary"`
}

// depCoord is one declared dependency: an ecosystem/name/version coordinate
// plus the manifest file it came from. Parsing produces coordinates; matching
// (embedded advisories or a live OSV query) consumes them.
type depCoord struct {
	rel  string // manifest file, repo-relative
	eco  string // go | npm | pypi
	name string
	ver  string
}

type advisoryDB struct {
	byKey map[string]advisory // "eco\x00name\x00version"
}

func advKey(eco, name, ver string) string { return eco + "\x00" + name + "\x00" + ver }

func loadAdvisoryDB() (*advisoryDB, error) {
	b, err := advisoryFS.ReadFile("advisories.yaml")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Advisories []advisory `yaml:"advisories"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	db := &advisoryDB{byKey: map[string]advisory{}}
	for _, a := range doc.Advisories {
		db.byKey[advKey(a.Ecosystem, a.Name, a.Version)] = a
	}
	return db, nil
}

func (db *advisoryDB) match(rel, eco, name, ver string) []findings.Finding {
	a, ok := db.byKey[advKey(eco, name, ver)]
	if !ok {
		return nil
	}
	sev := findings.SeverityHigh
	if a.Severity != "" && findings.Severity(a.Severity).Valid() {
		sev = findings.Severity(a.Severity)
	}
	f := findings.Finding{
		RuleID:      "D1.vulnerable-dependency",
		Class:       "D1",
		Title:       "Dependency has a known vulnerability",
		Severity:    sev,
		Confidence:  findings.ConfidenceFirm,
		Modes:       []findings.Mode{findings.ModeWhite},
		Target:      findings.Target{Source: rel, Tool: name + "@" + ver},
		Evidence:    findings.Evidence{Note: a.ID + ": " + a.Summary},
		References:  []string{a.ID, "supply-chain"},
		Remediation: "Upgrade " + name + " to a patched version per the advisory.",
		StageStatus: findings.StageCompleted,
	}
	f.ID = f.Fingerprint()
	return []findings.Finding{f}
}

// matchCoords matches each coordinate against the embedded advisory set. It is
// the offline dependency check and the fallback when a live OSV lookup fails.
func (db *advisoryDB) matchCoords(coords []depCoord) []findings.Finding {
	var out []findings.Finding
	for _, c := range coords {
		out = append(out, db.match(c.rel, c.eco, c.name, c.ver)...)
	}
	return out
}

var goRequire = regexp.MustCompile(`^\s*([^\s]+)\s+v([^\s]+)`)

func parseGoMod(rel string, data []byte) []depCoord {
	var out []depCoord
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "require ")
		if m := goRequire.FindStringSubmatch(line); m != nil {
			out = append(out, depCoord{rel: rel, eco: "go", name: m[1], ver: m[2]})
		}
	}
	return out
}

func parsePackageJSON(rel string, data []byte) []depCoord {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	var out []depCoord
	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies} {
		for name, ver := range deps {
			out = append(out, depCoord{rel: rel, eco: "npm", name: name, ver: strings.TrimLeft(ver, "^~")})
		}
	}
	return out
}

var pyReq = regexp.MustCompile(`^\s*([A-Za-z0-9_.\-]+)==([^\s#]+)`)

func parseRequirements(rel string, data []byte) []depCoord {
	var out []depCoord
	for _, line := range strings.Split(string(data), "\n") {
		if m := pyReq.FindStringSubmatch(line); m != nil {
			out = append(out, depCoord{rel: rel, eco: "pypi", name: m[1], ver: m[2]})
		}
	}
	return out
}

// scanNPMScripts flags npm lifecycle scripts that run risky commands at install
// time (D2 supply-chain).
func scanNPMScripts(rel string, data []byte) []findings.Finding {
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	risky := regexp.MustCompile(`(?i)(curl|wget)\b.*\|\s*(sh|bash)|node\s+-e|rm\s+-rf|\beval\b`)
	var out []findings.Finding
	for name, script := range pkg.Scripts {
		lname := strings.ToLower(name)
		isInstall := lname == "preinstall" || lname == "install" || lname == "postinstall" || lname == "prepare"
		if isInstall && risky.MatchString(script) {
			f := findings.Finding{
				RuleID:      "D2.install-script",
				Class:       "D2",
				Title:       "Package install script runs a risky command",
				Severity:    findings.SeverityHigh,
				Confidence:  findings.ConfidenceFirm,
				Modes:       []findings.Mode{findings.ModeWhite},
				Target:      findings.Target{Source: rel, Tool: name},
				Evidence:    findings.Evidence{Note: name + ": " + script},
				References:  []string{"supply-chain", "malicious-package"},
				Remediation: "Install lifecycle scripts run automatically on npm install. Remove command execution from them or vendor a trusted build.",
				StageStatus: findings.StageCompleted,
			}
			f.ID = f.Fingerprint()
			out = append(out, f)
		}
	}
	return out
}
