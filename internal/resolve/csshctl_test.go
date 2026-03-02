package resolve

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveCSShCtl_EnvOverride(t *testing.T) {
	t.Setenv("CSSHCTL_PATH", "/custom/path/csshctl")
	got := ResolveCSShCtl()
	if got != "/custom/path/csshctl" {
		t.Fatalf("expected /custom/path/csshctl, got %s", got)
	}
}

func TestResolveCSShCtl_PathLookup(t *testing.T) {
	t.Setenv("CSSHCTL_PATH", "")
	// If csshctl is in PATH, we should get an absolute path back.
	if p, err := exec.LookPath("csshctl"); err == nil {
		got := ResolveCSShCtl()
		if !filepath.IsAbs(got) {
			t.Fatalf("expected absolute path, got %s (LookPath=%s)", got, p)
		}
	}
}

func TestResolveCSShCtl_SameDir(t *testing.T) {
	t.Setenv("CSSHCTL_PATH", "")
	// Temporarily shadow PATH to ensure LookPath fails.
	t.Setenv("PATH", "")

	exe, err := os.Executable()
	if err != nil {
		t.Skip("cannot determine executable path")
	}
	dir := filepath.Dir(exe)
	candidate := filepath.Join(dir, "csshctl")

	// Create a temporary csshctl next to the test binary.
	f, err := os.Create(candidate)
	if err != nil {
		t.Skip("cannot create temp csshctl next to test binary")
	}
	f.Close()
	defer os.Remove(candidate)

	got := ResolveCSShCtl()
	if got != candidate {
		t.Fatalf("expected %s, got %s", candidate, got)
	}
}

func TestResolveCSShCtl_Fallback(t *testing.T) {
	t.Setenv("CSSHCTL_PATH", "")
	t.Setenv("PATH", "")

	// Make sure there's no csshctl next to the test binary either.
	exe, err := os.Executable()
	if err != nil {
		t.Skip("cannot determine executable path")
	}
	candidate := filepath.Join(filepath.Dir(exe), "csshctl")
	os.Remove(candidate) // ensure it doesn't exist

	got := ResolveCSShCtl()
	if !strings.HasSuffix(got, "csshctl") {
		t.Fatalf("fallback should end with csshctl, got %s", got)
	}
	if got != "csshctl" {
		t.Fatalf("expected bare csshctl fallback, got %s", got)
	}
}
