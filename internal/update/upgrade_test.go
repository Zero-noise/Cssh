package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseChecksums(t *testing.T) {
	data := []byte("abc123  cssh-linux-amd64.tar.gz\ndef456  cssh-darwin-arm64.tar.gz\n")
	m := parseChecksums(data)
	if m["cssh-linux-amd64.tar.gz"] != "abc123" {
		t.Fatalf("got %q", m["cssh-linux-amd64.tar.gz"])
	}
	if m["cssh-darwin-arm64.tar.gz"] != "def456" {
		t.Fatalf("got %q", m["cssh-darwin-arm64.tar.gz"])
	}
}

func TestVerifySHA256(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "testfile")
	content := []byte("hello world")
	os.WriteFile(path, content, 0o600)

	h := sha256.Sum256(content)
	expected := fmt.Sprintf("%x", h)

	if err := verifySHA256(path, expected); err != nil {
		t.Fatalf("valid checksum failed: %v", err)
	}

	if err := verifySHA256(path, "deadbeef"); err == nil {
		t.Fatal("expected error for wrong checksum")
	}

	if err := verifySHA256(filepath.Join(tmp, "nonexistent"), expected); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestExtractTarGz(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.tar.gz")
	extractDir := filepath.Join(tmp, "out")
	os.MkdirAll(extractDir, 0o755)

	// Create a tar.gz with a test binary.
	createTarGz(t, archivePath, map[string]string{
		"cssh-mcp-test": "binary-content-mcp",
		"csshctl-test":  "binary-content-ctl",
	})

	if err := extractTarGz(archivePath, extractDir); err != nil {
		t.Fatalf("extractTarGz: %v", err)
	}

	// Verify files exist with correct content and permissions.
	for _, name := range []string{"cssh-mcp-test", "csshctl-test"} {
		path := filepath.Join(extractDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if name == "cssh-mcp-test" && string(data) != "binary-content-mcp" {
			t.Fatalf("%s content = %q", name, data)
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("%s is not executable: %v", name, info.Mode())
		}
	}
}

func TestExtractTarGzRejectsPathTraversal(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "evil.tar.gz")
	extractDir := filepath.Join(tmp, "out")
	os.MkdirAll(extractDir, 0o755)

	createTarGzWithHeaders(t, archivePath, []tar.Header{
		{Name: "../escape", Typeflag: tar.TypeReg, Size: 4, Mode: 0o755},
	}, []string{"evil"})

	if err := extractTarGz(archivePath, extractDir); err == nil {
		t.Fatal("expected error for path traversal")
	}
}

func TestExtractTarGzRejectsSymlink(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "symlink.tar.gz")
	extractDir := filepath.Join(tmp, "out")
	os.MkdirAll(extractDir, 0o755)

	createTarGzWithHeaders(t, archivePath, []tar.Header{
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
	}, []string{""})

	if err := extractTarGz(archivePath, extractDir); err == nil {
		t.Fatal("expected error for symlink")
	}
}

func TestReplaceWithRollback(t *testing.T) {
	tmp := t.TempDir()

	binaries := []struct{ extracted, target string }{
		{"cssh-mcp-test", "cssh-mcp"},
		{"csshctl-test", "csshctl"},
	}

	// Create current binaries.
	os.WriteFile(filepath.Join(tmp, "cssh-mcp"), []byte("old-mcp"), 0o755)
	os.WriteFile(filepath.Join(tmp, "csshctl"), []byte("old-ctl"), 0o755)

	// Create .new binaries.
	os.WriteFile(filepath.Join(tmp, "cssh-mcp.new"), []byte("new-mcp"), 0o755)
	os.WriteFile(filepath.Join(tmp, "csshctl.new"), []byte("new-ctl"), 0o755)

	if err := replaceWithRollback(tmp, binaries); err != nil {
		t.Fatalf("replaceWithRollback: %v", err)
	}

	// Verify new content.
	data, _ := os.ReadFile(filepath.Join(tmp, "cssh-mcp"))
	if string(data) != "new-mcp" {
		t.Fatalf("cssh-mcp = %q, want %q", data, "new-mcp")
	}
	data, _ = os.ReadFile(filepath.Join(tmp, "csshctl"))
	if string(data) != "new-ctl" {
		t.Fatalf("csshctl = %q, want %q", data, "new-ctl")
	}

	// Verify .old files were cleaned up.
	if _, err := os.Stat(filepath.Join(tmp, "cssh-mcp.old")); !os.IsNotExist(err) {
		t.Fatal("cssh-mcp.old should be removed")
	}
}

func TestReplaceWithRollbackOnFailure(t *testing.T) {
	tmp := t.TempDir()

	binaries := []struct{ extracted, target string }{
		{"cssh-mcp-test", "cssh-mcp"},
		{"csshctl-test", "csshctl"},
	}

	// Create current binaries.
	os.WriteFile(filepath.Join(tmp, "cssh-mcp"), []byte("old-mcp"), 0o755)
	os.WriteFile(filepath.Join(tmp, "csshctl"), []byte("old-ctl"), 0o755)

	// Create only cssh-mcp.new (csshctl.new missing to trigger rollback).
	os.WriteFile(filepath.Join(tmp, "cssh-mcp.new"), []byte("new-mcp"), 0o755)
	// csshctl.new intentionally not created

	err := replaceWithRollback(tmp, binaries)
	if err == nil {
		t.Fatal("expected error when csshctl.new is missing")
	}

	// Verify rollback: originals should be restored.
	data, _ := os.ReadFile(filepath.Join(tmp, "cssh-mcp"))
	if string(data) != "old-mcp" {
		t.Fatalf("cssh-mcp should be rolled back, got %q", data)
	}
	data, _ = os.ReadFile(filepath.Join(tmp, "csshctl"))
	if string(data) != "old-ctl" {
		t.Fatalf("csshctl should be rolled back, got %q", data)
	}
}

func TestUpgradeE2E(t *testing.T) {
	// Set up a fake install directory with "old" binaries.
	installDir := t.TempDir()
	os.WriteFile(filepath.Join(installDir, "cssh-mcp"), []byte("old-mcp"), 0o755)
	os.WriteFile(filepath.Join(installDir, "csshctl"), []byte("old-ctl"), 0o755)

	// Create a fake executable symlink so installDirectory() resolves to our temp dir.
	fakeExe := filepath.Join(installDir, "cssh-mcp")

	runtimeDir := t.TempDir()

	// Build a fake archive matching the actual runtime.
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	archiveName := fmt.Sprintf("cssh-%s-%s.tar.gz", goos, goarch)
	archiveContent := buildFakeArchive(t, goos, goarch)

	checksum := fmt.Sprintf("%x", sha256.Sum256(archiveContent))
	checksumsContent := fmt.Sprintf("%s  %s\n", checksum, archiveName)

	tag := "v9.9.9"

	// Serve fake GitHub release.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case fmt.Sprintf("/%s/releases/download/%s/checksums.txt", repo, tag):
			w.Write([]byte(checksumsContent))
		case fmt.Sprintf("/%s/releases/download/%s/%s", repo, tag, archiveName):
			w.Write(archiveContent)
		case fmt.Sprintf("/repos/%s/releases/latest", repo):
			json.NewEncoder(w).Encode(map[string]string{
				"tag_name": tag,
				"html_url": "https://example.com",
			})
		default:
			t.Logf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	origAPI := apiBaseURL
	origDL := downloadBaseURL
	apiBaseURL = srv.URL
	downloadBaseURL = srv.URL
	defer func() { apiBaseURL = origAPI; downloadBaseURL = origDL }()

	// Override installDirectory for test.
	origInstallDir := installDirectoryFn
	installDirectoryFn = func() (string, error) { return installDir, nil }
	defer func() { installDirectoryFn = origInstallDir }()

	release := &CheckResult{
		CurrentVersion:  "v0.1.0",
		LatestVersion:   tag,
		LatestTag:       tag,
		UpdateAvailable: true,
	}

	result, err := Upgrade(context.Background(), runtimeDir, release)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if result.NewVersion != tag {
		t.Fatalf("NewVersion = %q, want %q", result.NewVersion, tag)
	}

	// Verify binary was replaced.
	data, _ := os.ReadFile(fakeExe)
	if string(data) != "new-mcp-binary" {
		t.Fatalf("cssh-mcp content = %q, want %q", data, "new-mcp-binary")
	}
}

func TestUpgradeNilRelease(t *testing.T) {
	_, err := Upgrade(context.Background(), t.TempDir(), nil)
	if err == nil {
		t.Fatal("expected error for nil release")
	}
}

func TestUpgradeNoUpdateAvailable(t *testing.T) {
	release := &CheckResult{
		CurrentVersion:  "v1.0.0",
		LatestVersion:   "v1.0.0",
		LatestTag:       "v1.0.0",
		UpdateAvailable: false,
	}
	_, err := Upgrade(context.Background(), t.TempDir(), release)
	if err == nil {
		t.Fatal("expected error when no update available")
	}
}

func TestUpgradeChecksumMismatch(t *testing.T) {
	installDir := t.TempDir()
	os.WriteFile(filepath.Join(installDir, "cssh-mcp"), []byte("old"), 0o755)
	os.WriteFile(filepath.Join(installDir, "csshctl"), []byte("old"), 0o755)
	runtimeDir := t.TempDir()

	goos := runtime.GOOS
	goarch := runtime.GOARCH
	archiveName := fmt.Sprintf("cssh-%s-%s.tar.gz", goos, goarch)
	archiveContent := buildFakeArchive(t, goos, goarch)
	tag := "v9.9.9"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == fmt.Sprintf("/%s/releases/download/%s/checksums.txt", repo, tag):
			// Return wrong checksum.
			w.Write([]byte(fmt.Sprintf("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  %s\n", archiveName)))
		case r.URL.Path == fmt.Sprintf("/%s/releases/download/%s/%s", repo, tag, archiveName):
			w.Write(archiveContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	origDL := downloadBaseURL
	downloadBaseURL = srv.URL
	defer func() { downloadBaseURL = origDL }()

	origInstallDir := installDirectoryFn
	installDirectoryFn = func() (string, error) { return installDir, nil }
	defer func() { installDirectoryFn = origInstallDir }()

	release := &CheckResult{LatestTag: tag, UpdateAvailable: true}
	_, err := Upgrade(context.Background(), runtimeDir, release)
	if err == nil {
		t.Fatal("expected error for checksum mismatch")
	}

	// Verify originals untouched.
	data, _ := os.ReadFile(filepath.Join(installDir, "cssh-mcp"))
	if string(data) != "old" {
		t.Fatalf("cssh-mcp should be untouched, got %q", data)
	}
}

func TestUpgradeDownload404(t *testing.T) {
	installDir := t.TempDir()
	os.WriteFile(filepath.Join(installDir, "cssh-mcp"), []byte("old"), 0o755)
	runtimeDir := t.TempDir()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	origDL := downloadBaseURL
	downloadBaseURL = srv.URL
	defer func() { downloadBaseURL = origDL }()

	origInstallDir := installDirectoryFn
	installDirectoryFn = func() (string, error) { return installDir, nil }
	defer func() { installDirectoryFn = origInstallDir }()

	release := &CheckResult{LatestTag: "v9.9.9", UpdateAvailable: true}
	_, err := Upgrade(context.Background(), runtimeDir, release)
	if err == nil {
		t.Fatal("expected error for 404 download")
	}
}

func TestUpgradeMissingBinaryInArchive(t *testing.T) {
	installDir := t.TempDir()
	os.WriteFile(filepath.Join(installDir, "cssh-mcp"), []byte("old"), 0o755)
	os.WriteFile(filepath.Join(installDir, "csshctl"), []byte("old"), 0o755)
	runtimeDir := t.TempDir()

	goos := runtime.GOOS
	goarch := runtime.GOARCH
	archiveName := fmt.Sprintf("cssh-%s-%s.tar.gz", goos, goarch)

	// Build archive with ONLY cssh-mcp, missing csshctl.
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "archive.tar.gz")
	createTarGz(t, archivePath, map[string]string{
		fmt.Sprintf("cssh-mcp-%s-%s", goos, goarch): "new-mcp",
		// csshctl intentionally missing
	})
	archiveContent, _ := os.ReadFile(archivePath)

	checksum := fmt.Sprintf("%x", sha256.Sum256(archiveContent))
	tag := "v9.9.9"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == fmt.Sprintf("/%s/releases/download/%s/checksums.txt", repo, tag):
			w.Write([]byte(fmt.Sprintf("%s  %s\n", checksum, archiveName)))
		case r.URL.Path == fmt.Sprintf("/%s/releases/download/%s/%s", repo, tag, archiveName):
			w.Write(archiveContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	origDL := downloadBaseURL
	downloadBaseURL = srv.URL
	defer func() { downloadBaseURL = origDL }()

	origInstallDir := installDirectoryFn
	installDirectoryFn = func() (string, error) { return installDir, nil }
	defer func() { installDirectoryFn = origInstallDir }()

	release := &CheckResult{LatestTag: tag, UpdateAvailable: true}
	_, err := Upgrade(context.Background(), runtimeDir, release)
	if err == nil {
		t.Fatal("expected error for missing binary in archive")
	}

	// Verify originals untouched.
	data, _ := os.ReadFile(filepath.Join(installDir, "cssh-mcp"))
	if string(data) != "old" {
		t.Fatalf("cssh-mcp should be untouched, got %q", data)
	}
}

// ── Test helpers ────────────────────────────────────────

func createTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	for name, content := range files {
		tw.WriteHeader(&tar.Header{
			Name:     name,
			Size:     int64(len(content)),
			Mode:     0o755,
			Typeflag: tar.TypeReg,
		})
		tw.Write([]byte(content))
	}
}

func createTarGzWithHeaders(t *testing.T, path string, headers []tar.Header, contents []string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	for i, h := range headers {
		tw.WriteHeader(&h)
		if i < len(contents) {
			tw.Write([]byte(contents[i]))
		}
	}
}

func buildFakeArchive(t *testing.T, goos, goarch string) []byte {
	t.Helper()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "archive.tar.gz")
	createTarGz(t, path, map[string]string{
		fmt.Sprintf("cssh-mcp-%s-%s", goos, goarch): "new-mcp-binary",
		fmt.Sprintf("csshctl-%s-%s", goos, goarch):  "new-ctl-binary",
	})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
