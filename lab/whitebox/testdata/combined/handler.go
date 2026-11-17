package combined

import "os/exec"

// handleRun passes untrusted input to a shell (C1): exercises the white-box
// analyzer within a combined submission.
func handleRun(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}
