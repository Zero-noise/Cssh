package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"cssh/internal/filelock"
	"cssh/internal/version"
)

// downloadBaseURL can be overridden in tests.
var downloadBaseURL = "https://github.com"

// UpgradeResult holds the outcome of an upgrade.
type UpgradeResult struct {
	PreviousVersion string `json:"previous_version"`
	NewVersion      string `json:"new_version"`
}

// Upgrade downloads the release described by result and replaces the local binaries.
// The release's LatestTag is used to construct pinned download URLs (not "latest").
func Upgrade(ctx context.Context, runtimeDir string, release *CheckResult) (*UpgradeResult, error) {
	if release == nil || !release.UpdateAvailable {
		return nil, fmt.Errorf("upgrade: no update available")
	}

	// Cross-process lock to prevent concurrent upgrades from corrupting staging/backup files.
	lockPath := filepath.Join(runtimeDir, "upgrade")
	unlock, err := filelock.Lock(lockPath)
	if err != nil {
		return nil, fmt.Errorf("upgrade: acquire lock: %w", err)
	}
	defer unlock()

	tag := release.LatestTag
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	archiveName := fmt.Sprintf("cssh-%s-%s.tar.gz", goos, goarch)

	// Determine install directory from the running executable.
	installDir, err := installDirectoryFn()
	if err != nil {
		return nil, fmt.Errorf("upgrade: %w", err)
	}

	// Create temp directory inside installDir (same filesystem for atomic rename).
	tmpDir, err := os.MkdirTemp(installDir, ".cssh-upgrade-*")
	if err != nil {
		return nil, fmt.Errorf("upgrade: create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Download checksums.txt and archive pinned to the exact tag.
	baseURL := fmt.Sprintf("%s/%s/releases/download/%s", downloadBaseURL, repo, tag)

	checksumsPath := filepath.Join(tmpDir, "checksums.txt")
	if err := downloadToFile(ctx, baseURL+"/checksums.txt", checksumsPath); err != nil {
		return nil, fmt.Errorf("upgrade: download checksums: %w", err)
	}

	archivePath := filepath.Join(tmpDir, archiveName)
	if err := downloadToFile(ctx, baseURL+"/"+archiveName, archivePath); err != nil {
		return nil, fmt.Errorf("upgrade: download archive: %w", err)
	}

	// Parse checksums and verify.
	checksumsData, err := os.ReadFile(checksumsPath)
	if err != nil {
		return nil, fmt.Errorf("upgrade: read checksums: %w", err)
	}
	checksums := parseChecksums(checksumsData)
	expected, ok := checksums[archiveName]
	if !ok {
		return nil, fmt.Errorf("upgrade: no checksum found for %s", archiveName)
	}
	if err := verifySHA256(archivePath, expected); err != nil {
		return nil, err
	}

	// Extract archive.
	extractDir := filepath.Join(tmpDir, "extracted")
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return nil, fmt.Errorf("upgrade: mkdir extracted: %w", err)
	}
	if err := extractTarGz(archivePath, extractDir); err != nil {
		return nil, fmt.Errorf("upgrade: extract: %w", err)
	}

	// Identify extracted binaries (named cssh-mcp-{os}-{arch} and csshctl-{os}-{arch}).
	binaries := []struct {
		extracted string // name in archive
		target    string // name in install dir
	}{
		{fmt.Sprintf("cssh-mcp-%s-%s", goos, goarch), "cssh-mcp"},
		{fmt.Sprintf("csshctl-%s-%s", goos, goarch), "csshctl"},
	}

	// Verify all extracted files exist before starting replacement.
	for _, b := range binaries {
		src := filepath.Join(extractDir, b.extracted)
		if _, err := os.Stat(src); err != nil {
			return nil, fmt.Errorf("upgrade: expected binary %s not found in archive", b.extracted)
		}
	}

	// Stage: copy extracted binaries to installDir as <name>.new with correct permissions.
	for _, b := range binaries {
		src := filepath.Join(extractDir, b.extracted)
		dst := filepath.Join(installDir, b.target+".new")
		if err := copyFile(src, dst, 0o755); err != nil {
			return nil, fmt.Errorf("upgrade: stage %s: %w", b.target, err)
		}
	}

	// Replace with rollback support.
	if err := replaceWithRollback(installDir, binaries); err != nil {
		return nil, err
	}

	// Update cache.
	cachePath := filepath.Join(runtimeDir, "update-check.json")
	updated := &CheckResult{
		CurrentVersion:  tag,
		LatestVersion:   tag,
		LatestTag:       tag,
		UpdateAvailable: false,
		ReleaseURL:      release.ReleaseURL,
		CheckedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	_ = writeCache(cachePath, updated)

	return &UpgradeResult{
		PreviousVersion: version.Short(),
		NewVersion:      tag,
	}, nil
}

// replaceWithRollback performs a two-phase replacement with rollback on failure.
// Phase A: rename current → .old
// Phase B: rename .new → current
// On failure in Phase B, .old files are restored.
func replaceWithRollback(installDir string, binaries []struct{ extracted, target string }) error {
	type done struct {
		target string
		oldOK  bool // .old was created
		newOK  bool // .new was renamed to target
	}
	var completed []done

	rollback := func() {
		for i := len(completed) - 1; i >= 0; i-- {
			d := completed[i]
			if d.newOK {
				// Move the new file back to .new
				_ = os.Rename(filepath.Join(installDir, d.target), filepath.Join(installDir, d.target+".new"))
			}
			if d.oldOK {
				// Restore from .old
				_ = os.Rename(filepath.Join(installDir, d.target+".old"), filepath.Join(installDir, d.target))
			}
		}
		// Clean up any remaining .new files.
		for _, b := range binaries {
			_ = os.Remove(filepath.Join(installDir, b.target+".new"))
		}
	}

	// Phase A: rename current → .old (only if current exists).
	for _, b := range binaries {
		d := done{target: b.target}
		currentPath := filepath.Join(installDir, b.target)
		oldPath := currentPath + ".old"
		if _, err := os.Stat(currentPath); err == nil {
			if err := os.Rename(currentPath, oldPath); err != nil {
				rollback()
				return fmt.Errorf("upgrade: backup %s: %w", b.target, err)
			}
			d.oldOK = true
		}
		completed = append(completed, d)
	}

	// Phase B: rename .new → current.
	for i, b := range binaries {
		newPath := filepath.Join(installDir, b.target+".new")
		currentPath := filepath.Join(installDir, b.target)
		if err := os.Rename(newPath, currentPath); err != nil {
			rollback()
			return fmt.Errorf("upgrade: install %s: %w", b.target, err)
		}
		completed[i].newOK = true
	}

	// Clean up .old files (best-effort).
	for _, b := range binaries {
		_ = os.Remove(filepath.Join(installDir, b.target+".old"))
	}

	return nil
}

// installDirectoryFn is the default implementation; overridable in tests.
var installDirectoryFn = installDirectory

// installDirectory returns the directory containing the running executable.
func installDirectory() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}
	return filepath.Dir(exe), nil
}

func downloadToFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "cssh/"+version.Short())

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return f.Close()
}

func verifySHA256(filePath, expectedHex string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("checksum: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("checksum: %w", err)
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if actual != expectedHex {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHex, actual)
	}
	return nil
}

// parseChecksums parses a checksums.txt file (sha256sum format: "<hash>  <filename>").
func parseChecksums(data []byte) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// sha256sum uses two spaces between hash and filename.
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			m[parts[len(parts)-1]] = parts[0]
		}
	}
	return m
}

func extractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Security: reject absolute paths, path traversal, and symlinks.
		name := filepath.Clean(header.Name)
		if filepath.IsAbs(name) || strings.Contains(name, "..") {
			return fmt.Errorf("unsafe path in archive: %s", header.Name)
		}
		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			return fmt.Errorf("symlink/hardlink rejected: %s", header.Name)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}

		dest := filepath.Join(destDir, name)
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		out.Close()

		// Ensure executable permission regardless of tar header.
		if err := os.Chmod(dest, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Chmod(perm); err != nil {
		return err
	}
	return out.Close()
}
