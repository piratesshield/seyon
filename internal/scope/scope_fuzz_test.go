package scope

import "testing"

// FuzzParse checks that scope parsing never panics and, critically, never
// returns a usable scope for malformed input — a parse failure must fail closed
// (no scope), never enable active probing by accident.
func FuzzParse(f *testing.F) {
	f.Add([]byte("allow_active: true\ntargets:\n  - x\n"))
	f.Add([]byte("allow_active: false\n"))
	f.Add([]byte(""))
	f.Add([]byte("targets: [a, b]"))
	f.Add([]byte(": : : not yaml"))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := Parse(data)
		if err == nil {
			// A successful parse must be a genuinely authorizing scope.
			if !s.AllowActive || len(s.Targets) == 0 {
				t.Fatalf("Parse returned a non-authorizing scope without error: %+v", s)
			}
		}
	})
}
