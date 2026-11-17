package surface

import "testing"

// FuzzParse checks that surface-snapshot parsing never panics on arbitrary
// bytes. A malformed tools/list snapshot must fail cleanly.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"tools":[{"name":"echo","description":"d"}]}`))
	f.Add([]byte(`{"tools":[]}`))
	f.Add([]byte(`{"prompts":[{"name":"p"}]}`))
	f.Add([]byte(``))
	f.Add([]byte(`[1,2,3]`))
	f.Fuzz(func(_ *testing.T, data []byte) {
		if Looks(data) {
			_, _ = Parse(data, "fuzz")
		}
		_, _ = Parse(data, "fuzz")
	})
}
