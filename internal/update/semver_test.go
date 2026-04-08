package update

import "testing"

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"v1.0.0", "v1.0.1", -1},
		{"v1.0.1", "v1.0.0", 1},
		{"v1.0.0", "v1.0.0", 0},
		{"v1.1.0", "v1.0.0", 1},
		{"v1.0.0", "v1.1.0", -1},
		{"v2.0.0", "v1.0.0", 1},
		{"v1.0.0", "v2.0.0", -1},
		{"v2.0.0", "v1.99.99", 1},
		{"1.2.3", "1.2.3", 0},
		{"v1.2.3", "1.2.3", 0},

		// dev is always smallest
		{"dev", "v0.0.1", -1},
		{"v0.0.1", "dev", 1},
		{"dev", "dev", 0},

		// pre-release is less than release (semver spec)
		{"v1.2.3-rc1", "v1.2.3", -1},
		{"v1.2.3", "v1.2.3-rc1", 1},
		{"v1.2.3-rc1", "v1.2.3-rc2", 0}, // both have pre-release → equal (no lexicographic)
		{"v1.2.3-beta", "v1.2.4", -1},

		// plus build metadata suffix
		{"v1.2.3+build", "v1.2.3", -1}, // has suffix → treated as pre-release
		{"v1.2.3-rc1+build123", "v1.2.3", -1},

		// invalid strings treated as dev
		{"", "v1.0.0", -1},
		{"garbage", "v1.0.0", -1},
		{"v1.0", "v1.0.0", -1},
		{"garbage", "garbage", 0},
		{"v", "v1.0.0", -1},
		{"v1.2.a", "v1.0.0", -1},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got := CompareSemver(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("CompareSemver(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestParseSemver(t *testing.T) {
	tests := []struct {
		input               string
		major, minor, patch int
		pre                 string
		ok                  bool
	}{
		{"v1.2.3", 1, 2, 3, "", true},
		{"0.1.0", 0, 1, 0, "", true},
		{"v10.20.30", 10, 20, 30, "", true},
		{"v1.2.3-rc1", 1, 2, 3, "rc1", true},
		{"v1.2.3+build", 1, 2, 3, "build", true},
		{"v1.2.3-rc1+build", 1, 2, 3, "rc1+build", true},
		{"dev", 0, 0, 0, "", false},
		{"", 0, 0, 0, "", false},
		{"v1.2", 0, 0, 0, "", false},
		{"abc", 0, 0, 0, "", false},
		{"v", 0, 0, 0, "", false},
		{"v1.2.a", 0, 0, 0, "", false},
		{"v-1.2.3", 0, 0, 0, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			maj, min, pat, pre, ok := parseSemver(tt.input)
			if ok != tt.ok || maj != tt.major || min != tt.minor || pat != tt.patch || pre != tt.pre {
				t.Errorf("parseSemver(%q) = (%d,%d,%d,%q,%v), want (%d,%d,%d,%q,%v)",
					tt.input, maj, min, pat, pre, ok, tt.major, tt.minor, tt.patch, tt.pre, tt.ok)
			}
		})
	}
}
