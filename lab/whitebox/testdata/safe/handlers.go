package safe

import (
	"database/sql"
	"os"
)

// readConfig reads a fixed, trusted path (no untrusted input reaches it).
func readConfig() ([]byte, error) {
	return os.ReadFile("/etc/seyon/config.yaml")
}

// lookup uses a parameterized query, so the id never becomes part of the SQL text.
func lookup(db *sql.DB, id string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM items WHERE id = ?", id)
}
