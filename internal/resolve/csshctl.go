package resolve

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ResolveCSShCtl returns the best available path for the csshctl executable.
// Priority: CSSHCTL_PATH env > PATH lookup > same directory as current executable > fallback "csshctl".
func ResolveCSShCtl() string {
	if p := os.Getenv("CSSHCTL_PATH"); p != "" {
		return p
	}
	if p, err := exec.LookPath("csshctl"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
		return p
	}
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "csshctl")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "csshctl"
}

// QuotedPath returns the resolved csshctl path, shell-quoted if it contains spaces.
func QuotedPath() string {
	p := ResolveCSShCtl()
	if strings.Contains(p, " ") {
		return `"` + p + `"`
	}
	return p
}
