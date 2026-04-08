package update

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckLatest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/Zero-noise/Cssh/releases/latest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"tag_name": "v0.2.0",
			"html_url": "https://github.com/Zero-noise/Cssh/releases/tag/v0.2.0",
		})
	}))
	defer srv.Close()

	orig := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = orig }()

	result, err := CheckLatest(context.Background(), "v0.1.0")
	if err != nil {
		t.Fatalf("CheckLatest: %v", err)
	}
	if !result.UpdateAvailable {
		t.Fatal("expected UpdateAvailable=true")
	}
	if result.LatestTag != "v0.2.0" {
		t.Fatalf("LatestTag = %q, want %q", result.LatestTag, "v0.2.0")
	}
	if result.CurrentVersion != "v0.1.0" {
		t.Fatalf("CurrentVersion = %q, want %q", result.CurrentVersion, "v0.1.0")
	}
}

func TestCheckLatestAlreadyUpToDate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"tag_name": "v1.0.0",
			"html_url": "https://example.com",
		})
	}))
	defer srv.Close()

	orig := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = orig }()

	result, err := CheckLatest(context.Background(), "v1.0.0")
	if err != nil {
		t.Fatalf("CheckLatest: %v", err)
	}
	if result.UpdateAvailable {
		t.Fatal("expected UpdateAvailable=false")
	}
}

func TestCheckLatestCachedFresh(t *testing.T) {
	tmp := t.TempDir()
	cachePath := filepath.Join(tmp, "update-check.json")

	// Write a fresh cache entry.
	cached := &CheckResult{
		CurrentVersion:  "v0.1.0",
		LatestVersion:   "v0.3.0",
		LatestTag:       "v0.3.0",
		UpdateAvailable: true,
		CheckedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(cached)
	os.WriteFile(cachePath, data, 0o600)

	// Server should not be called (cache is fresh).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be called when cache is fresh")
	}))
	defer srv.Close()

	orig := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = orig }()

	result, err := CheckLatestCached(context.Background(), tmp, "v0.1.0", 24*time.Hour)
	if err != nil {
		t.Fatalf("CheckLatestCached: %v", err)
	}
	if !result.UpdateAvailable {
		t.Fatal("expected UpdateAvailable=true from cache")
	}
	if result.LatestTag != "v0.3.0" {
		t.Fatalf("LatestTag = %q, want %q", result.LatestTag, "v0.3.0")
	}
}

func TestCheckLatestCachedStale(t *testing.T) {
	tmp := t.TempDir()
	cachePath := filepath.Join(tmp, "update-check.json")

	// Write a stale cache entry.
	cached := &CheckResult{
		CurrentVersion:  "v0.1.0",
		LatestVersion:   "v0.2.0",
		LatestTag:       "v0.2.0",
		UpdateAvailable: true,
		CheckedAt:       time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(cached)
	os.WriteFile(cachePath, data, 0o600)

	// Server returns newer version.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"tag_name": "v0.4.0",
			"html_url": "https://example.com",
		})
	}))
	defer srv.Close()

	orig := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = orig }()

	result, err := CheckLatestCached(context.Background(), tmp, "v0.1.0", 24*time.Hour)
	if err != nil {
		t.Fatalf("CheckLatestCached: %v", err)
	}
	if result.LatestTag != "v0.4.0" {
		t.Fatalf("LatestTag = %q, want %q (should fetch fresh)", result.LatestTag, "v0.4.0")
	}
}

func TestCheckLatestCachedNetworkFailureFallback(t *testing.T) {
	tmp := t.TempDir()
	cachePath := filepath.Join(tmp, "update-check.json")

	// Write a stale cache entry.
	cached := &CheckResult{
		CurrentVersion:  "v0.1.0",
		LatestVersion:   "v0.2.0",
		LatestTag:       "v0.2.0",
		UpdateAvailable: true,
		CheckedAt:       time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(cached)
	os.WriteFile(cachePath, data, 0o600)

	// Server returns error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	orig := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = orig }()

	result, err := CheckLatestCached(context.Background(), tmp, "v0.1.0", 24*time.Hour)
	if err != nil {
		t.Fatalf("should fall back to stale cache, got error: %v", err)
	}
	if result.LatestTag != "v0.2.0" {
		t.Fatalf("LatestTag = %q, want %q (stale cache fallback)", result.LatestTag, "v0.2.0")
	}
}

func TestCheckLatestHTTPErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"not_found", http.StatusNotFound},
		{"forbidden", http.StatusForbidden},
		{"rate_limited", http.StatusTooManyRequests},
		{"server_error", http.StatusInternalServerError},
		{"bad_gateway", http.StatusBadGateway},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			orig := apiBaseURL
			apiBaseURL = srv.URL
			defer func() { apiBaseURL = orig }()

			_, err := CheckLatest(context.Background(), "v0.1.0")
			if err == nil {
				t.Fatalf("expected error for HTTP %d", tt.status)
			}
		})
	}
}

func TestCheckLatestEmptyTagName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"tag_name": "", "html_url": ""})
	}))
	defer srv.Close()

	orig := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = orig }()

	_, err := CheckLatest(context.Background(), "v0.1.0")
	if err == nil {
		t.Fatal("expected error for empty tag_name")
	}
}

func TestCheckLatestMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	orig := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = orig }()

	_, err := CheckLatest(context.Background(), "v0.1.0")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestCheckLatestCancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // block forever
	}))
	defer srv.Close()

	orig := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, err := CheckLatest(ctx, "v0.1.0")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestCheckLatestCachedCorruptedCache(t *testing.T) {
	tmp := t.TempDir()
	cachePath := filepath.Join(tmp, "update-check.json")
	os.WriteFile(cachePath, []byte(`{corrupt json!!!`), 0o600)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"tag_name": "v0.5.0",
			"html_url": "https://example.com",
		})
	}))
	defer srv.Close()

	orig := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = orig }()

	result, err := CheckLatestCached(context.Background(), tmp, "v0.1.0", 24*time.Hour)
	if err != nil {
		t.Fatalf("should handle corrupted cache gracefully: %v", err)
	}
	if result.LatestTag != "v0.5.0" {
		t.Fatalf("LatestTag = %q, want %q (should fetch fresh after corrupted cache)", result.LatestTag, "v0.5.0")
	}
}

func TestCheckLatestCachedRefreshesCurrentVersion(t *testing.T) {
	// If binary was upgraded since cache was written, UpdateAvailable should reflect that.
	tmp := t.TempDir()
	cachePath := filepath.Join(tmp, "update-check.json")
	cached := &CheckResult{
		CurrentVersion:  "v0.1.0",
		LatestVersion:   "v0.2.0",
		LatestTag:       "v0.2.0",
		UpdateAvailable: true,
		CheckedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(cached)
	os.WriteFile(cachePath, data, 0o600)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not call server when cache is fresh")
	}))
	defer srv.Close()

	orig := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = orig }()

	// Asking with currentVersion == latest → update_available should be false
	result, err := CheckLatestCached(context.Background(), tmp, "v0.2.0", 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.UpdateAvailable {
		t.Fatal("expected UpdateAvailable=false after upgrade to latest")
	}
	if result.CurrentVersion != "v0.2.0" {
		t.Fatalf("CurrentVersion = %q, want %q", result.CurrentVersion, "v0.2.0")
	}
}

func TestCheckLatestCachedNoCache(t *testing.T) {
	tmp := t.TempDir()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"tag_name": "v0.5.0",
			"html_url": "https://example.com",
		})
	}))
	defer srv.Close()

	orig := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = orig }()

	result, err := CheckLatestCached(context.Background(), tmp, "v0.1.0", 24*time.Hour)
	if err != nil {
		t.Fatalf("CheckLatestCached: %v", err)
	}
	if result.LatestTag != "v0.5.0" {
		t.Fatalf("LatestTag = %q, want %q", result.LatestTag, "v0.5.0")
	}

	// Verify cache file was written.
	cachePath := filepath.Join(tmp, "update-check.json")
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		t.Fatal("cache file was not written")
	}
}
