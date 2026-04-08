package update

import (
	"strconv"
	"strings"
)

// CompareSemver compares two version strings and returns -1 (a < b),
// 0 (a == b), or +1 (a > b). Accepts "v1.2.3", "1.2.3", or "dev".
// "dev" is always considered less than any numeric version.
// Unparseable versions are treated the same as "dev".
// Per semver spec, a pre-release version (e.g. "v1.2.3-rc1") is less than
// the corresponding release version ("v1.2.3").
func CompareSemver(a, b string) int {
	amaj, amin, apat, apre, aok := parseSemver(a)
	bmaj, bmin, bpat, bpre, bok := parseSemver(b)

	if !aok && !bok {
		return 0
	}
	if !aok {
		return -1
	}
	if !bok {
		return 1
	}

	switch {
	case amaj != bmaj:
		return cmpInt(amaj, bmaj)
	case amin != bmin:
		return cmpInt(amin, bmin)
	case apat != bpat:
		return cmpInt(apat, bpat)
	default:
		// Same major.minor.patch: pre-release < release.
		// Both have pre-release or both don't → equal.
		if apre != "" && bpre == "" {
			return -1
		}
		if apre == "" && bpre != "" {
			return 1
		}
		return 0
	}
}

// parseSemver extracts major, minor, patch and pre-release from a version string.
// Returns ok=false for "dev", empty, or unparseable strings.
func parseSemver(s string) (major, minor, patch int, pre string, ok bool) {
	s = strings.TrimPrefix(s, "v")
	if s == "" || s == "dev" {
		return 0, 0, 0, "", false
	}
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return 0, 0, 0, "", false
	}
	// Extract pre-release suffix from patch (e.g. "3-rc1" → patch="3", pre="rc1").
	patchStr := parts[2]
	if idx := strings.IndexAny(patchStr, "-+"); idx >= 0 {
		pre = patchStr[idx+1:]
		patchStr = patchStr[:idx]
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return 0, 0, 0, "", false
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil || minor < 0 {
		return 0, 0, 0, "", false
	}
	patch, err = strconv.Atoi(patchStr)
	if err != nil || patch < 0 {
		return 0, 0, 0, "", false
	}
	return major, minor, patch, pre, true
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
