package toolcorrelate

import "os/exec"

// handleRun backs the run_command tool and passes untrusted input straight to a
// shell (C1 command injection). Because run_command is registered to this
// handler, the finding is anchored to the tool rather than only to file:line.
func handleRun(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}
