package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"cssh/internal/filelock"
	"cssh/internal/version"
)

const repo = "Zero-noise/Cssh"

// apiBaseURL can be overridden in tests.
var apiBaseURL = "https://api.github.com"

// CheckResult holds the outcome of a version check.
type CheckResult struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	LatestTag       string `json:"latest_tag"`
	UpdateAvailable bool   `json:"update_available"`
	ReleaseURL      string `json:"release_url,omitempty"`
	CheckedAt       string `json:"checked_at"`
}

// CheckLatest queries the GitHub API for the latest release.
func CheckLatest(ctx context.Context, currentVersion string) (*CheckResult, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", apiBaseURL, repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("update check: %w", err)
	}
	req.Header.Set("User-Agent", "cssh/"+version.Short())
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update check: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update check: GitHub API returned %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("update check: parse response: %w", err)
	}
	if release.TagName == "" {
		return nil, fmt.Errorf("update check: empty tag_name in response")
	}

	return &CheckResult{
		CurrentVersion:  currentVersion,
		LatestVersion:   release.TagName,
		LatestTag:       release.TagName,
		UpdateAvailable: CompareSemver(currentVersion, release.TagName) < 0,
		ReleaseURL:      release.HTMLURL,
		CheckedAt:       time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// CheckLatestCached returns a cached result if fresh, otherwise queries GitHub.
// maxAge controls how long the cache is considered valid.
// On network failure, returns a stale cache if available; if no cache exists,
// returns (nil, error).
func CheckLatestCached(ctx context.Context, runtimeDir, currentVersion string, maxAge time.Duration) (*CheckResult, error) {
	cachePath := filepath.Join(runtimeDir, "update-check.json")

	cached, cacheErr := readCache(cachePath)
	if cacheErr == nil && cached != nil {
		checkedAt, err := time.Parse(time.RFC3339, cached.CheckedAt)
		if err == nil && time.Since(checkedAt) < maxAge {
			// Refresh UpdateAvailable in case the binary was upgraded since cache was written.
			cached.CurrentVersion = currentVersion
			cached.UpdateAvailable = CompareSemver(currentVersion, cached.LatestTag) < 0
			return cached, nil
		}
	}

	result, err := CheckLatest(ctx, currentVersion)
	if err != nil {
		// Network failure: return stale cache if available.
		if cached != nil {
			cached.CurrentVersion = currentVersion
			cached.UpdateAvailable = CompareSemver(currentVersion, cached.LatestTag) < 0
			return cached, nil
		}
		return nil, err
	}

	_ = writeCache(cachePath, result)
	return result, nil
}

func readCache(path string) (*CheckResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result CheckResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func writeCache(path string, result *CheckResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	unlock, err := filelock.Lock(path)
	if err != nil {
		return err
	}
	defer unlock()
	return filelock.AtomicWrite(path, data, 0o600)
}
