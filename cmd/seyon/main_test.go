package main

import "testing"

func TestParseHeaders(t *testing.T) {
	h, err := parseHeaders([]string{"Authorization: Bearer abc", "X-Env:staging"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := h.Get("Authorization"); got != "Bearer abc" {
		t.Errorf("Authorization: got %q", got)
	}
	if got := h.Get("X-Env"); got != "staging" {
		t.Errorf("X-Env (no space after colon): got %q", got)
	}
}

func TestParseHeadersEmpty(t *testing.T) {
	h, err := parseHeaders(nil)
	if err != nil || h != nil {
		t.Errorf("empty input should yield (nil, nil), got (%v, %v)", h, err)
	}
}

func TestParseHeadersMalformed(t *testing.T) {
	for _, bad := range []string{"no-colon-here", ":novalue-key"} {
		if _, err := parseHeaders([]string{bad}); err == nil {
			t.Errorf("expected error for malformed header %q", bad)
		}
	}
}

func TestLooksLikeRepoURL(t *testing.T) {
	urls := []string{
		"https://github.com/org/repo",
		"http://gitlab.example/org/repo",
		"git@github.com:org/repo.git",
		"ssh://git@host/org/repo",
		"./vendored/repo.git",
	}
	for _, u := range urls {
		if !looksLikeRepoURL(u) {
			t.Errorf("%q should be treated as a repo URL", u)
		}
	}
	paths := []string{"./server-src", "/Users/apple/Documents/seyon", "lab/whitebox/testdata/vuln", "archive.zip"}
	for _, p := range paths {
		if looksLikeRepoURL(p) {
			t.Errorf("%q should be treated as a local path, not a repo URL", p)
		}
	}
}
