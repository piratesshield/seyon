package sast

import "testing"

// FuzzAnalyzeGo checks that the Go taint analyzer never panics on arbitrary
// input. Unparseable sources must be skipped, not crash the scan.
func FuzzAnalyzeGo(f *testing.F) {
	f.Add([]byte("package p\nfunc f(x string){ exec.Command(\"sh\",\"-c\",x) }"))
	f.Add([]byte("package p"))
	f.Add([]byte(""))
	f.Add([]byte("func ("))
	f.Add([]byte("package p\nfunc f(){ db.Query(\"a\"+b) }"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = analyzeGo("fuzz.go", data)
	})
}
