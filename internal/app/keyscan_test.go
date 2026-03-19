package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsPrivateKeyFile_PEM(t *testing.T) {
	dir := t.TempDir()
	// Create a fake PEM private key
	keyPath := filepath.Join(dir, "id_test")
	err := os.WriteFile(keyPath, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := entryForFile(dir, "id_test")
	if err != nil {
		t.Fatal(err)
	}
	if !isPrivateKeyFile(keyPath, entry) {
		t.Error("expected PEM file to be detected as private key")
	}
}

func TestIsPrivateKeyFile_Pub(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "id_test.pub")
	err := os.WriteFile(pubPath, []byte("ssh-ed25519 AAAA...\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := entryForFile(dir, "id_test.pub")
	if err != nil {
		t.Fatal(err)
	}
	if isPrivateKeyFile(pubPath, entry) {
		t.Error("expected .pub file to be rejected")
	}
}

func TestIsPrivateKeyFile_SkipKnownHosts(t *testing.T) {
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")
	err := os.WriteFile(khPath, []byte("host key\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := entryForFile(dir, "known_hosts")
	if err != nil {
		t.Fatal(err)
	}
	if isPrivateKeyFile(khPath, entry) {
		t.Error("expected known_hosts to be rejected")
	}
}

func TestIsPrivateKeyFile_SkipLargeFile(t *testing.T) {
	dir := t.TempDir()
	bigPath := filepath.Join(dir, "bigkey")
	data := make([]byte, 200*1024)
	copy(data, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"))
	err := os.WriteFile(bigPath, data, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := entryForFile(dir, "bigkey")
	if err != nil {
		t.Fatal(err)
	}
	if isPrivateKeyFile(bigPath, entry) {
		t.Error("expected large file to be rejected")
	}
}

func TestIsPrivateKeyFile_SkipSymlink(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real_key")
	err := os.WriteFile(realPath, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "link_key")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatal(err)
	}
	entry, err := entryForFile(dir, "link_key")
	if err != nil {
		t.Fatal(err)
	}
	if isPrivateKeyFile(linkPath, entry) {
		t.Error("expected symlink to be rejected")
	}
}

func TestIsPrivateKeyFile_SkipDirectory(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	entry, err := entryForFile(dir, "subdir")
	if err != nil {
		t.Fatal(err)
	}
	if isPrivateKeyFile(subDir, entry) {
		t.Error("expected directory to be rejected")
	}
}

func TestScanSSHKeys_OutsideHome(t *testing.T) {
	_, err := ScanSSHKeys("/tmp/definitely-not-home")
	if err == nil {
		t.Error("expected error for directory outside home")
	}
}

func TestScanSSHKeys_EmptyDir(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	scanDir := filepath.Join(tempHome, ".ssh")
	if err := os.Mkdir(scanDir, 0o700); err != nil {
		t.Fatal(err)
	}

	keys, err := ScanSSHKeys(scanDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestScanSSHKeys_FindsKey(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	scanDir := filepath.Join(tempHome, ".ssh")
	if err := os.Mkdir(scanDir, 0o700); err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(scanDir, "id_test")
	err := os.WriteFile(keyPath, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	// Also create a .pub which should be ignored
	pubPath := filepath.Join(scanDir, "id_test.pub")
	_ = os.WriteFile(pubPath, []byte("ssh-ed25519 AAAA...\n"), 0o644)

	keys, err := ScanSSHKeys(scanDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Name != "id_test" {
		t.Errorf("expected name=id_test, got %s", keys[0].Name)
	}
}

func entryForFile(dir, name string) (os.DirEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Name() == name {
			return e, nil
		}
	}
	return nil, os.ErrNotExist
}
