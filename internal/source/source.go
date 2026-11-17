// Package source is Seyon's ingestion layer. It resolves the many ways a user
// can submit a target — a local path, an uploaded archive, a Git repo, a pasted
// config, or a live endpoint — into one normalized handle the analyzers
// consume. Phase 0 implements the local path resolver and endpoint-spec parsing;
// Git, archive, and inline resolvers arrive in later phases.
package source

// Kind is the sort of resolved input.
type Kind int

const (
	// KindDir is a directory tree on disk (a source checkout).
	KindDir Kind = iota
	// KindFile is a single file on disk (e.g. an mcp.json).
	KindFile
)

func (k Kind) String() string {
	switch k {
	case KindDir:
		return "dir"
	case KindFile:
		return "file"
	default:
		return "unknown"
	}
}

// Resolved is a normalized input handle. Root is an absolute path on disk.
type Resolved struct {
	Kind Kind
	Root string
	// Origin records how the input was submitted, for the report (e.g.
	// "local:/path", "git:github.com/org/repo@ref").
	Origin string
}
