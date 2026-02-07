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
