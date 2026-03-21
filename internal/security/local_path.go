package security

import (
	"errors"
	"fmt"
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

// ValidateLocalDirSymlinks walks a directory and ensures no symlink target
// escapes the directory root. This prevents uploading directories containing
// symlinks that point to sensitive files outside the transfer root, and
// catches dangerous symlinks in downloaded directories.
func ValidateLocalDirSymlinks(dirPath string) error {
	root, err := filepath.Abs(dirPath)
	if err != nil {
		return fmt.Errorf("resolve dir path: %w", err)
	}
	// Resolve the root itself in case it's a symlink.
	rootResolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve dir symlinks: %w", err)
	}
	return filepath.WalkDir(rootResolved, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink == 0 {
			return nil
		}
		target, err := filepath.EvalSymlinks(p)
		if err != nil {
			return fmt.Errorf("resolve symlink %s: %w", p, err)
		}
		rel, err := filepath.Rel(rootResolved, target)
		if err != nil {
			return fmt.Errorf("compute relative path for %s: %w", p, err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("symlink %s escapes directory root (target: %s)", p, target)
		}
		return nil
	})
}

// NormalizeAllowedLocalPaths resolves, canonicalizes, and deduplicates a list
// of allowed local paths. Each entry is run through ResolveLocalPath (abs +
// clean + symlink resolution) so that "/tmp", "/private/tmp", "/tmp/../tmp"
// all collapse to the same canonical value. Empty or invalid entries cause an
// error.
func NormalizeAllowedLocalPaths(paths []string) ([]string, error) {
	seen := map[string]bool{}
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		resolved, err := ResolveLocalPath(p)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed_local_path %q: %w", p, err)
		}
		if !seen[resolved] {
			seen[resolved] = true
			result = append(result, resolved)
		}
	}
	return result, nil
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
