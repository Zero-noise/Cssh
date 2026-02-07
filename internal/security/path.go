package security

import (
	"path"
	"strings"
)

func NormalizeRemotePath(input, cwd string) string {
	if input == "" {
		if cwd == "" {
			return "/"
		}
		return path.Clean(cwd)
	}
	if strings.HasPrefix(input, "/") {
		return path.Clean(input)
	}
	base := cwd
	if base == "" {
		base = "/"
	}
	return path.Clean(path.Join(base, input))
}

func IsWithinRoots(target string, roots []string) bool {
	target = path.Clean(target)
	for _, root := range roots {
		r := path.Clean(root)
		if r == "/" {
			return true
		}
		if target == r || strings.HasPrefix(target, r+"/") {
			return true
		}
	}
	return false
}
