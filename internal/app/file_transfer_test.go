package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cssh/internal/errorsx"
	"cssh/internal/security"
	"cssh/internal/sshbridge"
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
	if err := ensureLocalPathAllowed(inside, nil, false); err != nil {
		t.Fatalf("inside path should be allowed: %v", err)
	}
	if err := ensureLocalPathAllowed(outside, nil, false); err == nil {
		t.Fatalf("outside path should be denied when allow_local_anywhere=false")
	}
	if err := ensureLocalPathAllowed(outside, nil, true); err != nil {
		t.Fatalf("outside path should be allowed when allow_local_anywhere=true: %v", err)
	}
}

func TestEnsureLocalPathAllowed_Whitelist(t *testing.T) {
	tmp := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir tmp: %v", err)
	}

	// Create an allowed directory outside cwd
	allowed := t.TempDir()
	allowedFile, err := security.ResolveLocalPath(filepath.Join(allowed, "data.txt"))
	if err != nil {
		t.Fatalf("resolve allowed: %v", err)
	}
	outside, err := security.ResolveLocalPath(filepath.Join(filepath.Dir(tmp), "secret.key"))
	if err != nil {
		t.Fatalf("resolve outside: %v", err)
	}

	allowedPaths := []string{allowed}

	// Path in whitelist should pass without allow_local_anywhere
	if err := ensureLocalPathAllowed(allowedFile, allowedPaths, false); err != nil {
		t.Fatalf("whitelisted path should be allowed: %v", err)
	}

	// Path NOT in whitelist and NOT in cwd should be rejected
	if err := ensureLocalPathAllowed(outside, allowedPaths, false); err == nil {
		t.Fatalf("non-whitelisted outside path should be denied")
	}

	// Empty whitelist falls back to cwd-only
	if err := ensureLocalPathAllowed(allowedFile, nil, false); err == nil {
		t.Fatalf("should be denied with empty whitelist")
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

func TestValidateResumeMode(t *testing.T) {
	if err := validateResumeMode("overwrite"); err != nil {
		t.Fatalf("overwrite should allow resume: %v", err)
	}
	err := validateResumeMode("create")
	ce, ok := err.(*errorsx.CsshError)
	if !ok || ce.Code != errorsx.CodeInvalidParams {
		t.Fatalf("expected invalid params for create+resume, got %#v", err)
	}
}

func TestHasLocalRsyncUsesLookPath(t *testing.T) {
	orig := lookPath
	t.Cleanup(func() { lookPath = orig })

	lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	if !hasLocalRsync() {
		t.Fatalf("expected local rsync to be available")
	}

	lookPath = func(file string) (string, error) { return "", os.ErrNotExist }
	if hasLocalRsync() {
		t.Fatalf("expected local rsync to be unavailable")
	}
}

func TestResumeUnavailableError(t *testing.T) {
	cases := []struct {
		localOK  bool
		remoteOK bool
		want     string
	}{
		{localOK: false, remoteOK: false, want: "locally and on the remote host"},
		{localOK: false, remoteOK: true, want: "local rsync is unavailable"},
		{localOK: true, remoteOK: false, want: "remote host has no rsync"},
	}
	for _, tc := range cases {
		err := resumeUnavailableError(tc.localOK, tc.remoteOK)
		ce, ok := err.(*errorsx.CsshError)
		if !ok || ce.Code != errorsx.CodeResumeUnavailable {
			t.Fatalf("unexpected error for local=%v remote=%v: %#v", tc.localOK, tc.remoteOK, err)
		}
		if !strings.Contains(ce.Message, tc.want) {
			t.Fatalf("unexpected message: %q", ce.Message)
		}
		if !strings.Contains(ce.Message, "retry without resume=true") {
			t.Fatalf("message should explain retry path: %q", ce.Message)
		}
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

func TestTransferAuditDetailIncludesProtocolAndFallback(t *testing.T) {
	got := transferAuditDetail("a -> b", sshbridge.TransferResult{
		Protocol:       "scp_legacy",
		FallbackUsed:   true,
		FallbackReason: "sftp server unavailable",
	})
	if !strings.Contains(got, "protocol=scp_legacy") {
		t.Fatalf("detail should include protocol, got=%q", got)
	}
	if !strings.Contains(got, "fallback_used=true") {
		t.Fatalf("detail should include fallback flag, got=%q", got)
	}
	if !strings.Contains(got, "fallback_reason=sftp server unavailable") {
		t.Fatalf("detail should include fallback reason, got=%q", got)
	}
}

func TestTransferAuditDetailWithoutProtocol(t *testing.T) {
	got := transferAuditDetail("a -> b", sshbridge.TransferResult{})
	if got != "a -> b" {
		t.Fatalf("unexpected detail without protocol: %q", got)
	}
}

func TestDirectoryVerificationResult(t *testing.T) {
	typ, result, err := directoryVerificationResult(false, 3, 2)
	if err != nil || typ != "none" || result != "skipped" {
		t.Fatalf("disabled verification mismatch: type=%q result=%q err=%v", typ, result, err)
	}

	typ, result, err = directoryVerificationResult(true, 3, 3)
	if err != nil || typ != "file_count" || result != "match" {
		t.Fatalf("match verification mismatch: type=%q result=%q err=%v", typ, result, err)
	}

	typ, result, err = directoryVerificationResult(true, 3, 2)
	if err == nil || typ != "file_count" || result != "mismatch" {
		t.Fatalf("mismatch verification should fail: type=%q result=%q err=%v", typ, result, err)
	}
}

func TestLocalDirStats(t *testing.T) {
	tmp := t.TempDir()
	// Create a directory with 3 files of known sizes
	sub := filepath.Join(tmp, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	for _, f := range []struct {
		name string
		size int
	}{
		{"a.txt", 100},
		{"b.txt", 200},
		{"sub/c.txt", 50},
	} {
		if err := os.WriteFile(filepath.Join(tmp, f.name), make([]byte, f.size), 0o644); err != nil {
			t.Fatalf("write %s: %v", f.name, err)
		}
	}
	count, total, err := localDirStats(tmp)
	if err != nil {
		t.Fatalf("localDirStats: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 files, got %d", count)
	}
	if total != 350 {
		t.Fatalf("expected 350 bytes total, got %d", total)
	}
}

func TestLocalDirStatsEmpty(t *testing.T) {
	tmp := t.TempDir()
	count, total, err := localDirStats(tmp)
	if err != nil {
		t.Fatalf("localDirStats: %v", err)
	}
	if count != 0 || total != 0 {
		t.Fatalf("expected 0/0, got %d/%d", count, total)
	}
}

func TestLocalDirStatsRecursiveFlagOnRegularFile(t *testing.T) {
	// When recursive=true is passed with a regular file path, the service
	// silently sets recursive=false. This test verifies localDirStats is
	// only called for actual directories (it would error on a regular file).
	tmp := t.TempDir()
	f := filepath.Join(tmp, "file.txt")
	if err := os.WriteFile(f, []byte("data"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// localDirStats on a file path should still work — it walks the "directory"
	// and finds no regular files within (the path itself is the root).
	// Actually filepath.WalkDir on a regular file will visit just that file.
	count, total, err := localDirStats(f)
	if err != nil {
		t.Fatalf("localDirStats on file: %v", err)
	}
	if count != 1 || total != 4 {
		t.Fatalf("unexpected count/total: %d/%d", count, total)
	}
}
