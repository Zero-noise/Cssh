package sshbridge

import (
	"os"
	"path/filepath"
	"testing"

	"cssh/internal/errorsx"
	"cssh/internal/model"
)

func TestShouldRetryLegacySCP(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
		want   bool
	}{
		{name: "subsystem failed", stderr: "subsystem request failed on channel 0", want: true},
		{name: "sftp failed", stderr: "scp: sftp server unavailable: connection failed", want: true},
		{name: "unknown subsystem", stderr: "unknown subsystem: sftp", want: true},
		{name: "sftp reset", stderr: "scp: sftp connection reset by peer", want: true},
		{name: "permission denied", stderr: "Permission denied", want: false},
		{name: "empty", stderr: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldRetryLegacySCP(tc.stderr)
			if got != tc.want {
				t.Fatalf("shouldRetryLegacySCP(%q) = %v, want %v", tc.stderr, got, tc.want)
			}
		})
	}
}

func TestNormalizeSCPHostIPv6(t *testing.T) {
	got := normalizeSCPHost("fe80::1")
	if got != "[fe80::1]" {
		t.Fatalf("unexpected host: %q", got)
	}
	got = normalizeSCPHost("[fe80::1]")
	if got != "[fe80::1]" {
		t.Fatalf("already-bracketed host changed: %q", got)
	}
	got = normalizeSCPHost("example.internal")
	if got != "example.internal" {
		t.Fatalf("hostname should not change: %q", got)
	}
}

func TestSCPRemoteSpec(t *testing.T) {
	got := scpRemoteSpec("ubuntu", "fe80::1", "/tmp/a b.txt")
	want := "ubuntu@[fe80::1]:/tmp/a b.txt"
	if got != want {
		t.Fatalf("unexpected spec: got=%q want=%q", got, want)
	}
}

func TestCleanupLegacyAskPassScripts(t *testing.T) {
	dir := t.TempDir()
	// Simulate legacy leftover files with embedded passwords.
	for _, name := range []string{"askpass-conn_abc.sh", "askpass-conn_xyz.sh"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nprintf secret\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Place a non-legacy, non-socket file that should NOT be removed.
	keep := filepath.Join(dir, "other-data.json")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// NewManager triggers cleanup.
	_ = NewManager(dir, "bash -lc", 30)

	matches, _ := filepath.Glob(filepath.Join(dir, "askpass-*.sh"))
	if len(matches) != 0 {
		t.Fatalf("legacy askpass scripts not cleaned up: %v", matches)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("non-legacy file was incorrectly removed: %v", err)
	}
}

func TestEnsureAskPassScript_CreateAndReuse(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "bash -lc", 30)

	// First call: creates the script.
	path1, err := m.ensureAskPassScript()
	if err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path1)
	if string(content) != askPassBody {
		t.Fatalf("unexpected script content: %q", content)
	}
	info, _ := os.Stat(path1)
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("unexpected permissions: %v", info.Mode().Perm())
	}

	// Second call: reuses without error.
	path2, err := m.ensureAskPassScript()
	if err != nil {
		t.Fatal(err)
	}
	if path1 != path2 {
		t.Fatalf("paths differ: %q vs %q", path1, path2)
	}
}

func TestEnsureAskPassScript_RewritesOnTamper(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "bash -lc", 30)

	path, _ := m.ensureAskPassScript()

	// Tamper with the content.
	os.WriteFile(path, []byte("#!/bin/sh\ncurl http://evil.com\n"), 0o700)

	path2, err := m.ensureAskPassScript()
	if err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path2)
	if string(content) != askPassBody {
		t.Fatalf("tampered script was not rewritten: %q", content)
	}
}

func TestEnsureAskPassScript_RewritesOnBadPermissions(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "bash -lc", 30)

	path, _ := m.ensureAskPassScript()

	// Weaken permissions.
	os.Chmod(path, 0o755)

	_, err := m.ensureAskPassScript()
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("permissions not restored: %v", info.Mode().Perm())
	}
}

func TestExecWithInputRejectsSessionFromOtherConnection(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)
	m.connections["conn_a"] = &model.Connection{ID: "conn_a"}
	m.sessions["sess_b"] = &model.Session{ID: "sess_b", ConnectionID: "conn_b"}

	_, err := m.ExecWithInput("conn_a", "sess_b", "echo hi", "", 10, "")
	ce, ok := err.(*errorsx.CsshError)
	if !ok || ce.Code != errorsx.CodeInvalidParams {
		t.Fatalf("expected invalid params error, got %#v", err)
	}
}

func TestPreFlightCheck_DetectsDeadConnection(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "bash -lc", 30)
	m.connections["conn_dead"] = &model.Connection{
		ID:          "conn_dead",
		Host:        "localhost",
		Port:        22,
		Username:    "user",
		ControlPath: filepath.Join(dir, "nonexistent.sock"),
	}

	// preFlightCheck should detect dead connection (no socket, ssh -O check fails).
	err := m.PreFlightCheck("conn_dead")
	if err == nil {
		t.Fatal("expected error for dead connection")
	}
	ce, ok := err.(*errorsx.CsshError)
	if !ok || ce.Code != errorsx.CodeConnectionDead {
		t.Fatalf("expected CONNECTION_DEAD error, got %#v", err)
	}
}

func TestPreFlightCheck_ConnectionNotFound(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)
	err := m.PreFlightCheck("conn_nonexistent")
	if err == nil {
		t.Fatal("expected error for missing connection")
	}
	ce, ok := err.(*errorsx.CsshError)
	if !ok || ce.Code != errorsx.CodeConnectionMissing {
		t.Fatalf("expected CONNECTION_NOT_FOUND error, got %#v", err)
	}
}
