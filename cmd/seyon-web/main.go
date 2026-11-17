package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"seyon/internal/auth"
	"seyon/internal/engine"
	"seyon/internal/report"
	"seyon/internal/scope"
	"seyon/internal/source"
)

//go:embed static
var staticFS embed.FS

var version = "2.0.0-beta"

// job tracks an async scan.
type job struct {
	ID        string         `json:"id"`
	Status    string         `json:"status"`
	Mode      string         `json:"mode"`
	Target    string         `json:"target"`
	CreatedAt time.Time      `json:"created_at"`
	Report    *report.Report `json:"report,omitempty"`
	Error     string         `json:"error,omitempty"`
	Consent   *consentRecord `json:"consent,omitempty"`
	// Headers are extra HTTP headers to send to the target (e.g. Authorization).
	// Not serialized — they can carry secrets.
	Headers http.Header `json:"-"`
	// Toggles are per-stage on/off flags from the UI.
	Toggles *engine.Toggles `json:"-"`
}

type consentRecord struct {
	Email     string    `json:"email"`
	IP        string    `json:"ip"`
	Accepted  bool      `json:"accepted"`
	Timestamp time.Time `json:"timestamp"`
}

var (
	jobs   = map[string]*job{}
	jobsMu sync.RWMutex
)

func newJobID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	addr := os.Getenv("SEYON_ADDR")
	if addr == "" {
		addr = ":9977"
	}

	mux := http.NewServeMux()

	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))

	mux.HandleFunc("POST /api/scan/github", handleGitHubScan)
	mux.HandleFunc("POST /api/scan/upload", handleUploadScan)
	mux.HandleFunc("POST /api/scan/blackbox", handleBlackboxScan)
	mux.HandleFunc("GET /api/scan/{id}", handleGetScan)

	srv := &http.Server{
		Addr:         addr,
		Handler:      withCORS(withRateLimit(mux)),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  2 * time.Minute,
	}

	log.Printf("seyon-web %s listening on %s", version, addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func handleGitHubScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		jsonError(w, "url is required", http.StatusBadRequest)
		return
	}
	if !isValidGitHubURL(req.URL) {
		jsonError(w, "only GitHub repository URLs are accepted", http.StatusBadRequest)
		return
	}

	j := &job{
		ID:        newJobID(),
		Status:    "running",
		Mode:      "white",
		Target:    req.URL,
		CreatedAt: time.Now().UTC(),
	}
	jobsMu.Lock()
	jobs[j.ID] = j
	jobsMu.Unlock()

	go runGitHubScan(j)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": j.ID, "status": "running"})
}

func handleUploadScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 100<<20)
	if err := r.ParseMultipartForm(100 << 20); err != nil {
		jsonError(w, "file too large (max 100MB)", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "file upload required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if !strings.HasSuffix(strings.ToLower(header.Filename), ".zip") {
		jsonError(w, "only .zip files are accepted", http.StatusBadRequest)
		return
	}

	data, err := io.ReadAll(io.LimitReader(file, 100<<20))
	if err != nil {
		jsonError(w, "failed to read upload", http.StatusInternalServerError)
		return
	}

	j := &job{
		ID:        newJobID(),
		Status:    "running",
		Mode:      "white",
		Target:    header.Filename,
		CreatedAt: time.Now().UTC(),
	}
	jobsMu.Lock()
	jobs[j.ID] = j
	jobsMu.Unlock()

	go runUploadScan(j, data)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": j.ID, "status": "running"})
}

func handleBlackboxScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL         string            `json:"url"`
		Email       string            `json:"email"`
		Consent     bool              `json:"consent"`
		BearerToken string            `json:"bearer_token,omitempty"`
		Headers     map[string]string `json:"headers,omitempty"`
		// OAuth 2.0 client credentials grant (two-legged, machine-to-machine).
		// When token_url + client_id are set, the scanner fetches an access
		// token before the scan and injects it as Authorization: Bearer <tok>.
		OAuthTokenURL     string   `json:"oauth_token_url,omitempty"`
		OAuthClientID     string   `json:"oauth_client_id,omitempty"`
		OAuthClientSecret string   `json:"oauth_client_secret,omitempty"`
		OAuthScopes       []string `json:"oauth_scopes,omitempty"`
		OAuthAudience     string   `json:"oauth_audience,omitempty"`
		// Toggles: per-stage on/off. Nil fields = default (on). The UI sends
		// pointer-bool JSON so "omitted" stays distinct from "explicitly off".
		Toggles *engine.Toggles `json:"toggles,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	req.Email = strings.TrimSpace(req.Email)
	req.BearerToken = strings.TrimSpace(req.BearerToken)

	if req.URL == "" {
		jsonError(w, "url is required", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		jsonError(w, "URL must start with http:// or https://", http.StatusBadRequest)
		return
	}
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		jsonError(w, "valid email is required for active scanning", http.StatusBadRequest)
		return
	}
	if !req.Consent {
		jsonError(w, "you must accept the consent notice to proceed", http.StatusBadRequest)
		return
	}

	// Build the HTTP header set the scanner will carry on every request to
	// the target. Three paths produce an Authorization header, in priority
	// order: explicit OAuth client-credentials, static bearer token, or
	// caller-supplied Authorization in Headers. Only the FIRST one that
	// succeeds is used, so a credential mix-up fails loudly instead of
	// silently layering two.
	hdr := http.Header{}
	if req.OAuthTokenURL != "" && req.OAuthClientID != "" {
		src, err := auth.NewClientCredentials(auth.ClientCredentialsConfig{
			TokenURL:     req.OAuthTokenURL,
			ClientID:     req.OAuthClientID,
			ClientSecret: req.OAuthClientSecret,
			Scopes:       req.OAuthScopes,
			Audience:     req.OAuthAudience,
		})
		if err != nil {
			jsonError(w, "oauth: "+err.Error(), http.StatusBadRequest)
			return
		}
		octx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		if err := auth.ApplyHeader(octx, src, hdr); err != nil {
			cancel()
			jsonError(w, "oauth token fetch failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		cancel()
	} else if req.BearerToken != "" {
		hdr.Set("Authorization", "Bearer "+req.BearerToken)
	}
	for k, v := range req.Headers {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		// Reject hop-by-hop headers and any attempt to overwrite our own
		// framing headers; everything else goes through.
		switch strings.ToLower(k) {
		case "host", "content-length", "transfer-encoding", "connection",
			"mcp-protocol-version", "mcp-session-id", "accept", "content-type":
			continue
		}
		hdr.Add(k, v)
	}

	clientIP := realIP(r)
	j := &job{
		ID:        newJobID(),
		Status:    "running",
		Mode:      "black",
		Target:    req.URL,
		CreatedAt: time.Now().UTC(),
		Consent: &consentRecord{
			Email:     req.Email,
			IP:        clientIP,
			Accepted:  true,
			Timestamp: time.Now().UTC(),
		},
		Headers: hdr,
		Toggles: req.Toggles,
	}
	jobsMu.Lock()
	jobs[j.ID] = j
	jobsMu.Unlock()

	go runBlackboxScan(j)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": j.ID, "status": "running"})
}

func handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	jobsMu.RLock()
	j, ok := jobs[id]
	jobsMu.RUnlock()
	if !ok {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(j)
}

func runGitHubScan(j *job) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log.Printf("scan %s: github clone %q", j.ID, j.Target)
	resolved, cleanup, err := source.GitClone(ctx, j.Target, "")
	if err != nil {
		log.Printf("scan %s: clone failed: %v", j.ID, err)
		finishJob(j, nil, fmt.Errorf("clone failed: %w", err))
		return
	}
	defer cleanup()

	r, err := engine.CombinedScan(ctx, version, resolved, nil, false)
	if err != nil {
		log.Printf("scan %s: github scan error: %v", j.ID, err)
	} else if r != nil {
		log.Printf("scan %s: github done findings=%d", j.ID, len(r.Findings))
	}
	finishJob(j, r, err)
}

func runUploadScan(j *job, data []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tmpDir, err := os.MkdirTemp("", "seyon-upload-*")
	if err != nil {
		finishJob(j, nil, err)
		return
	}
	defer os.RemoveAll(tmpDir)

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		finishJob(j, nil, fmt.Errorf("invalid zip: %w", err))
		return
	}

	var totalSize int64
	const maxTotal = 500 << 20
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := filepath.Clean(f.Name)
		if strings.Contains(name, "..") {
			finishJob(j, nil, fmt.Errorf("zip contains path traversal: %s", f.Name))
			return
		}
		dest := filepath.Join(tmpDir, name)
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			finishJob(j, nil, err)
			return
		}
		rc, err := f.Open()
		if err != nil {
			finishJob(j, nil, err)
			return
		}
		out, err := os.Create(dest)
		if err != nil {
			rc.Close()
			finishJob(j, nil, err)
			return
		}
		n, err := io.Copy(out, io.LimitReader(rc, maxTotal-totalSize))
		out.Close()
		rc.Close()
		if err != nil {
			finishJob(j, nil, err)
			return
		}
		totalSize += n
		if totalSize > maxTotal {
			finishJob(j, nil, fmt.Errorf("zip contents exceed 500MB limit"))
			return
		}
	}

	resolved, err := source.Local(tmpDir)
	if err != nil {
		finishJob(j, nil, err)
		return
	}
	r, err := engine.CombinedScan(ctx, version, resolved, nil, false)
	finishJob(j, r, err)
}

func runBlackboxScan(j *job) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	spec, err := source.ParseEndpoint(j.Target)
	if err != nil {
		log.Printf("scan %s: parse endpoint %q: %v", j.ID, j.Target, err)
		finishJob(j, nil, fmt.Errorf("invalid endpoint: %w", err))
		return
	}

	denyEgress := true
	sc := &scope.Scope{
		AllowActive:     true,
		Targets:         []string{j.Target},
		DenyEgress:      &denyEgress,
		MaxCallsPerTool: 3,
	}
	opts := engine.BlackOptions{
		Active:  true,
		Scope:   sc,
		Headers: j.Headers,
		Toggles: j.Toggles,
	}

	log.Printf("scan %s: blackbox start target=%q", j.ID, j.Target)
	r, err := engine.BlackScan(ctx, version, spec, opts)
	if err != nil {
		log.Printf("scan %s: blackbox error: %v", j.ID, err)
	} else if r != nil {
		findings := len(r.Findings)
		inv := "no inventory"
		if r.Inventory != nil {
			inv = fmt.Sprintf("transport=%s protocol=%s tools=%d",
				r.Inventory.Transport, r.Inventory.Protocol, r.Inventory.Tools)
		}
		log.Printf("scan %s: blackbox done findings=%d %s", j.ID, findings, inv)
	}
	finishJob(j, r, err)
}

func finishJob(j *job, r *report.Report, err error) {
	jobsMu.Lock()
	defer jobsMu.Unlock()
	j.Report = r
	if err != nil {
		j.Error = err.Error()
		switch {
		case r != nil && hasInventory(r):
			// Full scan — error is non-fatal (e.g. an enumerator warning).
			j.Status = "completed"
		case r != nil && len(r.Findings) > 0:
			// Handshake failed but we still produced posture findings (the
			// unauth protocol probes, recon classification, etc.). This is
			// Cisco's `mcp-scanner protocol` mode: no inventory, but a
			// useful report. Mark as 'posture' so the UI shows both the
			// error banner AND the findings table without framing it as a
			// hard failure.
			j.Status = "posture"
		default:
			// No usable output. True failure.
			j.Status = "error"
		}
	} else {
		j.Status = "completed"
	}
}

func hasInventory(r *report.Report) bool {
	return r != nil && r.Inventory != nil && r.Inventory.Server != ""
}

func isValidGitHubURL(u string) bool {
	u = strings.ToLower(u)
	return strings.HasPrefix(u, "https://github.com/") || strings.HasPrefix(u, "http://github.com/")
}

func realIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitorEntry
}

type visitorEntry struct {
	tokens    float64
	lastCheck time.Time
}

var limiter = &rateLimiter{visitors: make(map[string]*visitorEntry)}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, ok := rl.visitors[ip]
	if !ok {
		rl.visitors[ip] = &visitorEntry{tokens: 9, lastCheck: now}
		return true
	}

	elapsed := now.Sub(v.lastCheck).Seconds()
	v.tokens += elapsed * 0.2
	if v.tokens > 10 {
		v.tokens = 10
	}
	v.lastCheck = now

	if v.tokens < 1 {
		return false
	}
	v.tokens--
	return true
}

func withRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/scan") && r.Method == http.MethodPost {
			ip := realIP(r)
			if !limiter.allow(ip) {
				jsonError(w, "rate limit exceeded, please wait", http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
