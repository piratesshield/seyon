package sast

import (
	"testing"

	"seyon/internal/findings"
)

func onlyFinding(t *testing.T, fs []findings.Finding, class string) *findings.Finding {
	t.Helper()
	var hit *findings.Finding
	n := 0
	for i := range fs {
		if fs[i].Class == class {
			hit = &fs[i]
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly one %s finding, got %d: %+v", class, n, fs)
	}
	return hit
}

func TestPythonTaintReachesSinkIsFirm(t *testing.T) {
	src := "import os\ndef h(cmd):\n    return os.system(cmd)\n"
	fs, ok := analyzePython("a.py", []byte(src))
	if !ok {
		t.Fatal("expected parse ok")
	}
	f := onlyFinding(t, fs, "C1")
	if f.Confidence != findings.ConfidenceFirm {
		t.Errorf("tainted param→sink should be firm, got %s", f.Confidence)
	}
}

func TestPythonLiteralArgIsClean(t *testing.T) {
	src := "import os\ndef h():\n    return os.system('ls')\n"
	fs, _ := analyzePython("a.py", []byte(src))
	if len(fs) != 0 {
		t.Errorf("literal command should produce no finding, got %+v", fs)
	}
}

func TestPythonNonConstNonTaintIsTentative(t *testing.T) {
	src := "import os\ndef h():\n    x = build()\n    return os.system(x)\n"
	fs, _ := analyzePython("a.py", []byte(src))
	f := onlyFinding(t, fs, "C1")
	if f.Confidence != findings.ConfidenceTentative {
		t.Errorf("non-literal, non-tainted should be tentative, got %s", f.Confidence)
	}
}

func TestPythonSSRFTainted(t *testing.T) {
	src := "import requests\ndef h(url):\n    return requests.get(url)\n"
	fs, _ := analyzePython("a.py", []byte(src))
	f := onlyFinding(t, fs, "C3")
	if f.Confidence != findings.ConfidenceFirm {
		t.Errorf("tainted URL should be firm C3, got %s", f.Confidence)
	}
}

func TestPythonSubprocessShellTrueBuiltString(t *testing.T) {
	src := "import subprocess\ndef h():\n    c = build()\n    return subprocess.run(c, shell=True)\n"
	fs, _ := analyzePython("a.py", []byte(src))
	onlyFinding(t, fs, "C1") // shell=True + non-literal command
}

func TestPythonSubprocessShellTrueLiteralIsClean(t *testing.T) {
	src := "import subprocess\ndef h():\n    return subprocess.run('ls -la', shell=True)\n"
	fs, _ := analyzePython("a.py", []byte(src))
	if len(fs) != 0 {
		t.Errorf("shell=True with a literal command is safe, got %+v", fs)
	}
}

func TestPythonSubprocessListArgvIsClean(t *testing.T) {
	src := "import subprocess\ndef h():\n    return subprocess.run(['generate', '--json'], check=True)\n"
	fs, _ := analyzePython("a.py", []byte(src))
	if len(fs) != 0 {
		t.Errorf("fixed list argv with no shell is safe, got %+v", fs)
	}
}

func TestPythonSQLConcatTainted(t *testing.T) {
	src := "def h(cursor, uid):\n    return cursor.execute('SELECT * FROM t WHERE id=' + uid)\n"
	fs, _ := analyzePython("a.py", []byte(src))
	f := onlyFinding(t, fs, "C4")
	if f.Confidence != findings.ConfidenceFirm {
		t.Errorf("tainted SQL concat should be firm, got %s", f.Confidence)
	}
}

func TestPythonSQLLiteralIsClean(t *testing.T) {
	src := "def h(cursor):\n    return cursor.execute('SELECT 1')\n"
	fs, _ := analyzePython("a.py", []byte(src))
	if len(fs) != 0 {
		t.Errorf("literal SQL should be clean, got %+v", fs)
	}
}

func TestPythonUnparseableReturnsNotOK(t *testing.T) {
	if _, ok := analyzePython("a.py", []byte("def h(:\n")); ok {
		t.Error("unparseable Python should return ok=false so the caller can fall back")
	}
}
