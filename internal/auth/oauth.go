// Package auth provides authentication helpers for Seyon's live scanner.
//
// The scanner needs an Authorization header on every request to many hosted
// MCP providers. There are three ways a caller can supply one:
//
//  1. Static bearer token — caller already has one; just pass it through.
//     This is the simplest path and covers personal access tokens.
//  2. OAuth 2.0 client credentials grant — service-to-service, two-legged.
//     Scanner presents client_id + client_secret to a token URL, receives a
//     short-lived access token, and uses it. No user interaction. This is
//     the right shape for CI/CD or scheduled scans against a managed gateway.
//  3. OAuth 2.0 authorization code — three-legged with a browser redirect.
//     Not implemented here; add it when a caller needs to scan their own
//     Google/Microsoft/GitHub scoped account.
//
// This file ships (1) and (2). Browser-based flows are out of scope.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TokenSource is anything that can produce an Authorization header value. The
// value should be the full header value (e.g. "Bearer eyJ...").
type TokenSource interface {
	AuthorizationHeader(ctx context.Context) (string, error)
}

// StaticBearer wraps a pre-obtained token so it can be used anywhere a
// TokenSource is expected.
type StaticBearer struct{ Token string }

// AuthorizationHeader implements TokenSource.
func (s StaticBearer) AuthorizationHeader(_ context.Context) (string, error) {
	t := strings.TrimSpace(s.Token)
	if t == "" {
		return "", errors.New("auth: empty bearer token")
	}
	if strings.Contains(t, " ") {
		// Caller already prefixed (e.g. "Bearer ...").
		return t, nil
	}
	return "Bearer " + t, nil
}

// ClientCredentialsConfig describes an OAuth 2.0 client-credentials client.
type ClientCredentialsConfig struct {
	// TokenURL is the identity provider's token endpoint. Required.
	TokenURL string
	// ClientID is issued by the provider. Required.
	ClientID string
	// ClientSecret is issued by the provider. Required for a confidential
	// client; omit for a public client (not typical for client-credentials).
	ClientSecret string
	// Scopes are the requested OAuth scopes; may be empty.
	Scopes []string
	// Audience is a provider-specific audience hint (Auth0/AWS Cognito/Okta
	// often require it). Sent as the "audience" form field when set.
	Audience string
	// ExtraForm lets the caller inject provider-specific form fields that the
	// standard client_credentials grant does not define.
	ExtraForm url.Values
	// HTTPClient overrides the default http.Client (useful for proxies).
	HTTPClient *http.Client
	// Leeway is how much before the stated expiry we treat a token as stale
	// and fetch a new one. Default 30s.
	Leeway time.Duration
}

// ClientCredentials is a TokenSource that caches an access token from an
// OAuth 2.0 client-credentials grant and refreshes it when near expiry.
// Safe for concurrent use.
type ClientCredentials struct {
	cfg    ClientCredentialsConfig
	client *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// NewClientCredentials constructs the token source. Returns an error only
// when required config is missing; no network call happens here.
func NewClientCredentials(cfg ClientCredentialsConfig) (*ClientCredentials, error) {
	if strings.TrimSpace(cfg.TokenURL) == "" {
		return nil, errors.New("oauth: TokenURL required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("oauth: ClientID required")
	}
	c := cfg.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Leeway <= 0 {
		cfg.Leeway = 30 * time.Second
	}
	return &ClientCredentials{cfg: cfg, client: c}, nil
}

// AuthorizationHeader returns a valid "Bearer <token>" string, fetching a new
// token from the IdP when the cached one is unset or near expiry.
func (c *ClientCredentials) AuthorizationHeader(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Until(c.expiry) > c.cfg.Leeway {
		return "Bearer " + c.token, nil
	}
	if err := c.fetchLocked(ctx); err != nil {
		return "", err
	}
	return "Bearer " + c.token, nil
}

// Invalidate forces the next AuthorizationHeader call to fetch a fresh token.
// Useful after a 401 response — the cached token might have been revoked
// server-side even if its stated expiry has not passed.
func (c *ClientCredentials) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = ""
	c.expiry = time.Time{}
}

// fetchLocked performs the POST. Caller must hold c.mu.
func (c *ClientCredentials) fetchLocked(ctx context.Context) error {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if len(c.cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(c.cfg.Scopes, " "))
	}
	if c.cfg.Audience != "" {
		form.Set("audience", c.cfg.Audience)
	}
	for k, vs := range c.cfg.ExtraForm {
		for _, v := range vs {
			form.Add(k, v)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// Prefer client_secret_basic when a secret is set; some IdPs (Okta) reject
	// client_id/secret in the body when Basic auth is expected.
	if c.cfg.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	} else {
		form.Set("client_id", c.cfg.ClientID)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("oauth: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 400 {
			snippet = snippet[:400] + "…"
		}
		return fmt.Errorf("oauth: token endpoint returned %d: %s", resp.StatusCode, snippet)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return fmt.Errorf("oauth: decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		if tok.Error != "" {
			return fmt.Errorf("oauth: %s: %s", tok.Error, tok.ErrorDescription)
		}
		return errors.New("oauth: token response had no access_token")
	}

	c.token = tok.AccessToken
	// Default to 5 minutes if the IdP didn't say.
	ttl := 5 * time.Minute
	if tok.ExpiresIn > 0 {
		ttl = time.Duration(tok.ExpiresIn) * time.Second
	}
	c.expiry = time.Now().Add(ttl)
	return nil
}

// tokenResponse covers both the success and the error shapes an OAuth 2.0
// token endpoint may return.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Scope            string `json:"scope,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// ApplyHeader is a convenience that fetches a header value and writes it onto
// the given http.Header. Returns the token source's error unchanged.
func ApplyHeader(ctx context.Context, src TokenSource, h http.Header) error {
	if src == nil || h == nil {
		return nil
	}
	v, err := src.AuthorizationHeader(ctx)
	if err != nil {
		return err
	}
	h.Set("Authorization", v)
	return nil
}
