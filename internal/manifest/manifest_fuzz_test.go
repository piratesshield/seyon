package manifest

import "testing"

// FuzzParse checks that configuration parsing never panics on arbitrary bytes.
// Parsing untrusted mcp.json content must fail cleanly, never crash the scan.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"mcpServers":{"s":{"command":"bash","args":["-c","x"]}}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`{"mcpServers":null}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(_ *testing.T, data []byte) {
		if Looks(data) {
			_, _ = Parse(data)
		}
		_, _ = Parse(data)
	})
}
