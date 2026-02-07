package security

import "testing"

func TestNormalizeAndWithinRoots(t *testing.T) {
	p := NormalizeRemotePath("../repo/file.txt", "/home/dev/work/project")
	if p != "/home/dev/work/repo/file.txt" {
		t.Fatalf("unexpected normalized path: %s", p)
	}
	if !IsWithinRoots("/home/dev/work/repo/file.txt", []string{"/home/dev/work"}) {
		t.Fatalf("expected path to be in roots")
	}
	if IsWithinRoots("/etc/passwd", []string{"/home/dev/work"}) {
		t.Fatalf("expected path outside roots")
	}
}
