package version

import "fmt"

// Build-time variables injected via -ldflags.
var (
	Tag    = "dev"
	Commit = "unknown"
	Date   = "unknown"
)

// Short returns the version tag (e.g. "v0.2.0" or "dev").
func Short() string { return Tag }

// Full returns a human-readable version string including commit and date.
func Full() string {
	if Tag == "dev" {
		return "dev"
	}
	return fmt.Sprintf("%s (%s, %s)", Tag, Commit, Date)
}

// IsDev reports whether this is a development build (no release tag injected).
func IsDev() bool { return Tag == "dev" }
