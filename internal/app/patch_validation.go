package app

import (
	"fmt"
	"strconv"
	"strings"

	"cssh/internal/errorsx"
	"cssh/internal/security"
)

func validatePatchTargets(base, patchUnified string, strip int, workspaceRoots []string) error {
	if strip < 0 {
		return errorsx.New(errorsx.CodeInvalidParams, "strip must be >= 0")
	}
	targets, err := extractPatchTargets(patchUnified, strip)
	if err != nil {
		return errorsx.New(errorsx.CodeInvalidParams, err.Error())
	}
	for _, target := range targets {
		resolved := security.NormalizeRemotePath(target, base)
		if !security.IsWithinRoots(resolved, workspaceRoots) {
			return errorsx.New(errorsx.CodePathForbidden, "patch target is outside workspace_roots: "+resolved)
		}
	}
	return nil
}

func extractPatchTargets(patchUnified string, strip int) ([]string, error) {
	lines := strings.Split(patchUnified, "\n")
	var (
		targets []string
		seen    = map[string]struct{}{}
		oldPath string
		oldLine int
		found   bool
	)

	for i, line := range lines {
		lineNo := i + 1
		switch {
		case strings.HasPrefix(line, "--- "):
			raw, err := parsePatchHeaderPath(line, "--- ")
			if err != nil {
				return nil, fmt.Errorf("invalid --- header at line %d: %w", lineNo, err)
			}
			oldPath = raw
			oldLine = lineNo
		case strings.HasPrefix(line, "+++ "):
			if oldPath == "" {
				return nil, fmt.Errorf("found +++ header at line %d without a preceding --- header", lineNo)
			}
			raw, err := parsePatchHeaderPath(line, "+++ ")
			if err != nil {
				return nil, fmt.Errorf("invalid +++ header at line %d: %w", lineNo, err)
			}
			blockTargets, err := normalizePatchTargets(oldPath, raw, strip)
			if err != nil {
				return nil, fmt.Errorf("invalid patch target near lines %d-%d: %w", oldLine, lineNo, err)
			}
			for _, target := range blockTargets {
				if _, ok := seen[target]; ok {
					continue
				}
				seen[target] = struct{}{}
				targets = append(targets, target)
			}
			oldPath = ""
			oldLine = 0
			found = true
		}
	}

	if oldPath != "" {
		return nil, fmt.Errorf("missing +++ header for --- header at line %d", oldLine)
	}
	if !found {
		return nil, fmt.Errorf("patch_unified does not contain any unified diff file headers")
	}
	return targets, nil
}

func normalizePatchTargets(oldPath, newPath string, strip int) ([]string, error) {
	var targets []string
	seen := map[string]struct{}{}
	for _, candidate := range []string{oldPath, newPath} {
		target, ok, err := stripPatchPath(candidate, strip)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	return targets, nil
}

func stripPatchPath(raw string, strip int) (string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, fmt.Errorf("empty patch path")
	}
	if raw == "/dev/null" {
		return "", false, nil
	}
	stripped, err := applyPatchStrip(raw, strip)
	if err != nil {
		return "", false, err
	}
	if stripped == "" {
		return "", false, fmt.Errorf("path %q is empty after strip", raw)
	}
	return stripped, true, nil
}

func applyPatchStrip(raw string, strip int) (string, error) {
	if strip == 0 {
		return raw, nil
	}
	path := raw
	for i := 0; i < strip; i++ {
		slash := strings.IndexByte(path, '/')
		if slash < 0 {
			return "", fmt.Errorf("path %q does not have %d leading slash-separated component(s)", raw, strip)
		}
		path = path[slash+1:]
	}
	return path, nil
}

func parsePatchHeaderPath(line, prefix string) (string, error) {
	rest, ok := strings.CutPrefix(line, prefix)
	if !ok {
		return "", fmt.Errorf("missing %s prefix", strings.TrimSpace(prefix))
	}
	if tab := strings.IndexByte(rest, '\t'); tab >= 0 {
		rest = rest[:tab]
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", fmt.Errorf("empty patch path")
	}
	if strings.HasPrefix(rest, "\"") {
		unquoted, err := strconv.Unquote(rest)
		if err != nil {
			return "", fmt.Errorf("invalid quoted path %q", rest)
		}
		return unquoted, nil
	}
	if strings.Contains(rest, " ") {
		return "", fmt.Errorf("unsupported unquoted path format %q", rest)
	}
	return rest, nil
}
