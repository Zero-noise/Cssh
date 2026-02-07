package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cssh/internal/errorsx"
	"cssh/internal/security"
)

func TestNormalizeTransferMode(t *testing.T) {
	mode, err := normalizeTransferMode("")
	if err != nil || mode != "create" {
		t.Fatalf("empty mode should default to create: mode=%q err=%v", mode, err)
	}
	mode, err = normalizeTransferMode("overwrite")
	if err != nil || mode != "overwrite" {
		t.Fatalf("overwrite mode mismatch: mode=%q err=%v", mode, err)
	}
	if _, err := normalizeTransferMode("append"); err == nil {
		t.Fatalf("append should be rejected for transfer mode")
	}
}

func TestEnsureChecksumsMatch(t *testing.T) {
	if err := ensureChecksumsMatch("abc", "abc"); err != nil {
		t.Fatalf("equal checksums should pass: %v", err)
	}
	err := ensureChecksumsMatch("abc", "def")
	ce, ok := err.(*errorsx.CsshError)
	if !ok || ce.Code != errorsx.CodeChecksumMismatch {
		t.Fatalf("expected checksum mismatch error, got: %#v", err)
	}
}

func TestEnsureLocalPathAllowed(t *testing.T) {
	tmp := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir tmp: %v", err)
	}

	inside, err := security.ResolveLocalPath(filepath.Join(tmp, "a.txt"))
	if err != nil {
		t.Fatalf("resolve inside: %v", err)
	}
	outside, err := security.ResolveLocalPath(filepath.Join(filepath.Dir(tmp), "b.txt"))
	if err != nil {
		t.Fatalf("resolve outside: %v", err)
	}
	if err := ensureLocalPathAllowed(inside, false); err != nil {
		t.Fatalf("inside path should be allowed: %v", err)
	}
	if err := ensureLocalPathAllowed(outside, false); err == nil {
		t.Fatalf("outside path should be denied when allow_local_anywhere=false")
	}
	if err := ensureLocalPathAllowed(outside, true); err != nil {
		t.Fatalf("outside path should be allowed when allow_local_anywhere=true: %v", err)
	}
}

func TestBuildRemoteSHA256Command(t *testing.T) {
	cmd := buildRemoteSHA256Command("/tmp/a b.txt")
	if !strings.Contains(cmd, "; elif") {
		t.Fatalf("checksum command should separate elif branch with semicolon: %q", cmd)
	}
	if !strings.Contains(cmd, "exit 127;") {
		t.Fatalf("checksum command should include explicit exit separator: %q", cmd)
	}
}

func TestInstallLocalCreateOnly(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "download.tmp")
	dst := filepath.Join(tmp, "result.txt")
	want := "hello"
	if err := os.WriteFile(src, []byte(want), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := installLocalCreateOnly(src, dst); err != nil {
		t.Fatalf("install create-only: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("source temp file should be removed, got err=%v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != want {
		t.Fatalf("unexpected content: got=%q want=%q", string(got), want)
	}
}

func TestInstallLocalCreateOnlyFileExists(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "download.tmp")
	dst := filepath.Join(tmp, "result.txt")
	if err := os.WriteFile(src, []byte("new"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := os.WriteFile(dst, []byte("old"), 0o644); err != nil {
		t.Fatalf("write dst: %v", err)
	}
	err := installLocalCreateOnly(src, dst)
	ce, ok := err.(*errorsx.CsshError)
	if !ok || ce.Code != errorsx.CodeFileExists {
		t.Fatalf("expected file exists error, got %#v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("source temp file should be removed on failure, got err=%v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != "old" {
		t.Fatalf("destination should keep old content, got=%q", string(got))
	}
}
