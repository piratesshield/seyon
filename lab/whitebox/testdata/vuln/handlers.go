package vuln

import (
	"database/sql"
	"net/http"
	"os"
	"os/exec"
)

// handleRun passes untrusted input straight to a shell (C1) and performs a
// sensitive operation with no authorization check (C6).
func handleRun(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}

// readUserFile reads an attacker-controlled path (C2).
func readUserFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// fetch requests an attacker-controlled URL (C3 SSRF).
func fetch(u string) (*http.Response, error) {
	return http.Get(u)
}

// lookup builds SQL by concatenation (C4).
func lookup(db *sql.DB, id string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM items WHERE id=" + id)
}
