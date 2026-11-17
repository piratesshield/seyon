package sast

import "testing"

// FuzzAnalyzePython checks that the Python dataflow analyzer never panics on
// arbitrary input: a malformed or exotic source must be skipped (ok=false),
// never crash the scan.
func FuzzAnalyzePython(f *testing.F) {
	f.Add([]byte("import os\ndef h(x):\n    return os.system(x)\n"))
	f.Add([]byte("def h():\n    subprocess.run(['a'], shell=True)\n"))
	f.Add([]byte(""))
	f.Add([]byte("def h(:\n"))
	f.Add([]byte("class C:\n    pass\n"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = analyzePython("fuzz.py", data)
	})
}

// FuzzAnalyzeJS checks that the JavaScript dataflow analyzer (goja parser plus
// the reflection walker) never panics on arbitrary input.
func FuzzAnalyzeJS(f *testing.F) {
	f.Add([]byte("function h(x){ return cp.exec(x); }"))
	f.Add([]byte("const x = `a${b}c`; fetch(x);"))
	f.Add([]byte(""))
	f.Add([]byte("function ("))
	f.Add([]byte("class C { m(a){ return eval(a); } }"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = analyzeJS("fuzz.js", data)
	})
}
