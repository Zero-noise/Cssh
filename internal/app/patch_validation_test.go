package app

import (
	"strings"
	"testing"

	"cssh/internal/errorsx"
)

func TestApplyPatchStrip(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		strip   int
		want    string
		wantErr string
	}{
		{name: "relative p0", raw: "a/b/c.txt", strip: 0, want: "a/b/c.txt"},
		{name: "relative p1", raw: "a/b/c.txt", strip: 1, want: "b/c.txt"},
		{name: "absolute p1", raw: "/u/howard/src/blurfl/blurfl.c", strip: 1, want: "u/howard/src/blurfl/blurfl.c"},
		{name: "absolute p4", raw: "/u/howard/src/blurfl/blurfl.c", strip: 4, want: "blurfl/blurfl.c"},
		{name: "strip too deep", raw: "foo.txt", strip: 1, wantErr: `does not have 1 leading slash-separated component(s)`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := applyPatchStrip(tc.raw, tc.strip)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractPatchTargetsSupportsQuotedPaths(t *testing.T) {
	patch := strings.Join([]string{
		`--- "a/dir/file name.txt"	2026-03-21 00:00:00`,
		`+++ "b/dir/file name.txt"	2026-03-21 00:00:00`,
		"@@ -1 +1 @@",
		"-old",
		"+new",
	}, "\n")

	targets, err := extractPatchTargets(patch, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 1 || targets[0] != "dir/file name.txt" {
		t.Fatalf("unexpected targets: %#v", targets)
	}
}

func TestValidatePatchTargetsRejectsParentTraversal(t *testing.T) {
	patch := strings.Join([]string{
		"--- ../escape.txt\t2026-03-21 00:00:00",
		"+++ ../escape.txt\t2026-03-21 00:00:00",
		"@@ -1 +1 @@",
		"-old",
		"+new",
	}, "\n")

	err := validatePatchTargets("/srv/app/sub", patch, 0, []string{"/srv/app/sub"})
	if err == nil {
		t.Fatal("expected error")
	}
	ce, ok := err.(*errorsx.CsshError)
	if !ok {
		t.Fatalf("expected CsshError, got %T", err)
	}
	if ce.Code != errorsx.CodePathForbidden {
		t.Fatalf("expected CodePathForbidden, got %s", ce.Code)
	}
}

func TestValidatePatchTargetsRejectsParentTraversalAfterStrip(t *testing.T) {
	patch := strings.Join([]string{
		"--- a/../escape.txt\t2026-03-21 00:00:00",
		"+++ b/../escape.txt\t2026-03-21 00:00:00",
		"@@ -1 +1 @@",
		"-old",
		"+new",
	}, "\n")

	err := validatePatchTargets("/srv/app/sub", patch, 1, []string{"/srv/app/sub"})
	if err == nil {
		t.Fatal("expected error")
	}
	ce, ok := err.(*errorsx.CsshError)
	if !ok {
		t.Fatalf("expected CsshError, got %T", err)
	}
	if ce.Code != errorsx.CodePathForbidden {
		t.Fatalf("expected CodePathForbidden, got %s", ce.Code)
	}
}

func TestValidatePatchTargetsRejectsAbsoluteTarget(t *testing.T) {
	patch := strings.Join([]string{
		"--- /etc/passwd\t2026-03-21 00:00:00",
		"+++ /etc/passwd\t2026-03-21 00:00:00",
		"@@ -1 +1 @@",
		"-root",
		"+pwned",
	}, "\n")

	err := validatePatchTargets("/srv/app", patch, 0, []string{"/srv/app"})
	if err == nil {
		t.Fatal("expected error")
	}
	ce, ok := err.(*errorsx.CsshError)
	if !ok {
		t.Fatalf("expected CsshError, got %T", err)
	}
	if ce.Code != errorsx.CodePathForbidden {
		t.Fatalf("expected CodePathForbidden, got %s", ce.Code)
	}
}

func TestValidatePatchTargetsAllowsCreateWithinRoots(t *testing.T) {
	patch := strings.Join([]string{
		"--- /dev/null\t2026-03-21 00:00:00",
		"+++ b/new/file.txt\t2026-03-21 00:00:00",
		"@@ -0,0 +1 @@",
		"+hello",
	}, "\n")

	if err := validatePatchTargets("/srv/app", patch, 1, []string{"/srv/app"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePatchTargetsRejectsMalformedPatch(t *testing.T) {
	patch := strings.Join([]string{
		"diff --git a/file.txt b/file.txt",
		"@@ -1 +1 @@",
		"-old",
		"+new",
	}, "\n")

	err := validatePatchTargets("/srv/app", patch, 1, []string{"/srv/app"})
	if err == nil {
		t.Fatal("expected error")
	}
	ce, ok := err.(*errorsx.CsshError)
	if !ok {
		t.Fatalf("expected CsshError, got %T", err)
	}
	if ce.Code != errorsx.CodeInvalidParams {
		t.Fatalf("expected CodeInvalidParams, got %s", ce.Code)
	}
}
