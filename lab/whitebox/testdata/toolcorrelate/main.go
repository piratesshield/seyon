package toolcorrelate

// register wires the server's tools. The run_command tool is backed by
// handleRun (defined in handlers.go), so a white-box sink found there anchors
// to the "run_command" tool and can correlate with the gray-box surface.
func register(s *server) {
	s.AddTool(mcp.NewTool("run_command", mcp.WithDescription("Run a helper command")), handleRun)
}
