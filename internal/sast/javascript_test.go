package sast

import (
	"testing"

	"seyon/internal/findings"
)

func TestJSExecTaintedIsFirm(t *testing.T) {
	src := "function h(cmd){ return cp.exec(cmd); }"
	fs, ok := analyzeJS("a.js", []byte(src))
	if !ok {
		t.Fatal("expected parse ok")
	}
	f := onlyFinding(t, fs, "C1")
	if f.Confidence != findings.ConfidenceFirm {
		t.Errorf("tainted exec should be firm, got %s", f.Confidence)
	}
}

func TestJSExecFileIsNotASink(t *testing.T) {
	src := "function h(cmd){ return cp.execFile('gen', [cmd]); }"
	fs, _ := analyzeJS("a.js", []byte(src))
	if len(fs) != 0 {
		t.Errorf("execFile with fixed program is not a shell sink, got %+v", fs)
	}
}

func TestJSExecLiteralIsClean(t *testing.T) {
	src := "function h(){ return cp.exec('ls'); }"
	fs, _ := analyzeJS("a.js", []byte(src))
	if len(fs) != 0 {
		t.Errorf("literal command should be clean, got %+v", fs)
	}
}

func TestJSEvalTainted(t *testing.T) {
	src := "function h(x){ return eval(x); }"
	fs, _ := analyzeJS("a.js", []byte(src))
	f := onlyFinding(t, fs, "C1")
	if f.Confidence != findings.ConfidenceFirm {
		t.Errorf("eval of tainted input should be firm, got %s", f.Confidence)
	}
}

func TestJSAssignmentPropagation(t *testing.T) {
	src := "function h(u){ let x = u; return fetch(x); }"
	fs, _ := analyzeJS("a.js", []byte(src))
	f := onlyFinding(t, fs, "C3")
	if f.Confidence != findings.ConfidenceFirm {
		t.Errorf("taint should propagate through assignment to fetch, got %s", f.Confidence)
	}
}

func TestJSFetchNonConstIsTentative(t *testing.T) {
	src := "function h(){ return fetch(buildURL()); }"
	fs, _ := analyzeJS("a.js", []byte(src))
	f := onlyFinding(t, fs, "C3")
	if f.Confidence != findings.ConfidenceTentative {
		t.Errorf("non-literal, non-tainted URL should be tentative, got %s", f.Confidence)
	}
}

func TestJSFsPathConcatTainted(t *testing.T) {
	src := "function h(name){ return fs.readFileSync('/data/' + name); }"
	fs, _ := analyzeJS("a.js", []byte(src))
	f := onlyFinding(t, fs, "C2")
	if f.Confidence != findings.ConfidenceFirm {
		t.Errorf("tainted path concat should be firm, got %s", f.Confidence)
	}
}

func TestJSTemplateLiteralTaint(t *testing.T) {
	src := "function h(c){ return cp.exec(`run ${c}`); }"
	fs, _ := analyzeJS("a.js", []byte(src))
	f := onlyFinding(t, fs, "C1")
	if f.Confidence != findings.ConfidenceFirm {
		t.Errorf("template literal with tainted substitution should be firm, got %s", f.Confidence)
	}
}

func TestJSNestedFunctionAttributedOnce(t *testing.T) {
	src := "function outer(a){ function inner(b){ return cp.exec(b); } return 1; }"
	fs, _ := analyzeJS("a.js", []byte(src))
	onlyFinding(t, fs, "C1") // exactly one: the sink in inner, not double-counted
}

func TestJSTypeScriptFallsBackToNotOK(t *testing.T) {
	// Type annotations are not valid JavaScript; goja should fail to parse, so
	// the analyzer reports ok=false and the caller falls back to patterns.
	src := "function h(x: string): void { eval(x); }"
	if _, ok := analyzeJS("a.ts", []byte(src)); ok {
		t.Error("TypeScript type syntax should not parse as JS; expected ok=false")
	}
}
