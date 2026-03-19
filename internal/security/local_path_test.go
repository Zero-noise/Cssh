package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveLocalPathRelative(t *testing.T) {
	tmp := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir tmp: %v", err)
	}

	got, err := ResolveLocalPath("./alpha/../beta.txt")
	if err != nil {
		t.Fatalf("resolve local path: %v", err)
	}
	want, err := ResolveLocalPath(filepath.Join(tmp, "beta.txt"))
	if err != nil {
		t.Fatalf("resolve expected path: %v", err)
	}
	if got != want {
		t.Fatalf("unexpected resolved path: got=%q want=%q", got, want)
	}
}

func TestIsWithinLocalRoot(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	inside := filepath.Join(root, "a", "file.txt")
	outside := filepath.Join(tmp, "outside.txt")

	if !IsWithinLocalRoot(inside, root) {
		t.Fatalf("inside path should be allowed")
	}
	if IsWithinLocalRoot(outside, root) {
		t.Fatalf("outside path should be denied")
	}
}

func TestAllowLocalAnywhereBehavior(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	outside := filepath.Join(tmp, "outside.txt")

	allowLocalAnywhere := false
	if allowLocalAnywhere || IsWithinLocalRoot(outside, root) {
		t.Fatalf("outside path should not be allowed when allow_local_anywhere is false")
	}

	allowLocalAnywhere = true
	if !(allowLocalAnywhere || IsWithinLocalRoot(outside, root)) {
		t.Fatalf("outside path should be allowed when allow_local_anywhere is true")
	}
}

func TestValidateLocalDirSymlinks_Safe(t *testing.T) {
	tmp := t.TempDir()
	sub := filepath.Join(tmp, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(sub, "real.txt")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Symlink within the directory
	link := filepath.Join(tmp, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := ValidateLocalDirSymlinks(tmp); err != nil {
		t.Fatalf("safe symlink should pass validation: %v", err)
	}
}

func TestValidateLocalDirSymlinks_Escape(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "dir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Create a file outside the directory
	outside := filepath.Join(tmp, "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Symlink inside dir pointing outside
	link := filepath.Join(dir, "escape.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := ValidateLocalDirSymlinks(dir)
	if err == nil {
		t.Fatalf("escaping symlink should fail validation")
	}
	if !filepath.IsAbs(outside) {
		t.Fatalf("test setup error: outside should be absolute")
	}
}

func TestValidateLocalDirSymlinks_NoSymlinks(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := ValidateLocalDirSymlinks(tmp); err != nil {
		t.Fatalf("dir without symlinks should pass: %v", err)
	}
}
