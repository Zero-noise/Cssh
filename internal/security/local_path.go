package security

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func ResolveLocalPath(input string) (string, error) {
	p := strings.TrimSpace(input)
	if p == "" {
		return "", errors.New("local path is empty")
	}
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	return canonicalLocalPath(filepath.Clean(abs)), nil
}

func IsWithinLocalRoot(target, root string) bool {
	t, err := ResolveLocalPath(target)
	if err != nil {
		return false
	}
	r, err := ResolveLocalPath(root)
	if err != nil {
		return false
	}
	t = canonicalLocalPath(t)
	r = canonicalLocalPath(r)
	rel, err := filepath.Rel(r, t)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func canonicalLocalPath(p string) string {
	clean := filepath.Clean(p)
	cur := clean
	suffix := make([]string, 0)
	for {
		if _, err := os.Lstat(cur); err == nil {
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		suffix = append([]string{filepath.Base(cur)}, suffix...)
		cur = parent
	}
	if resolved, err := filepath.EvalSymlinks(cur); err == nil {
		cur = resolved
	}
	for _, part := range suffix {
		cur = filepath.Join(cur, part)
	}
	return filepath.Clean(cur)
}
