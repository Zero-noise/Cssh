package version

import "testing"

func TestShortDefault(t *testing.T) {
	if got := Short(); got != "dev" {
		t.Fatalf("Short() = %q, want %q", got, "dev")
	}
}

func TestFullDefault(t *testing.T) {
	if got := Full(); got != "dev" {
		t.Fatalf("Full() = %q, want %q", got, "dev")
	}
}

func TestIsDevDefault(t *testing.T) {
	if !IsDev() {
		t.Fatal("IsDev() = false, want true")
	}
}

func TestFullWithTag(t *testing.T) {
	origTag, origCommit, origDate := Tag, Commit, Date
	defer func() { Tag, Commit, Date = origTag, origCommit, origDate }()

	Tag = "v1.2.3"
	Commit = "abc1234"
	Date = "2026-04-07"

	if got, want := Full(), "v1.2.3 (abc1234, 2026-04-07)"; got != want {
		t.Fatalf("Full() = %q, want %q", got, want)
	}
	if IsDev() {
		t.Fatal("IsDev() = true, want false")
	}
}
