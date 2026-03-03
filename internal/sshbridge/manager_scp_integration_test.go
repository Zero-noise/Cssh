package sshbridge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cssh/internal/errorsx"
	"cssh/internal/model"
)

func TestRunSCPReportsSFTPProtocolOnFirstSuccess(t *testing.T) {
	useMockSCP(t, "#!/bin/sh\nexit 0\n")

	m := NewManager(t.TempDir(), "bash -lc", 15)
	conn := &model.Connection{Port: 22, ControlPath: filepath.Join(t.TempDir(), "ctrl.sock")}

	res, err := m.runSCP(conn, "", 5, "src.txt", "dst.txt")
	if err != nil {
		t.Fatalf("runSCP unexpected error: %v", err)
	}
	if res.Protocol != transferProtocolSFTP {
		t.Fatalf("unexpected protocol: got=%q want=%q", res.Protocol, transferProtocolSFTP)
	}
	if res.FallbackUsed {
		t.Fatalf("fallback_used should be false")
	}
}

func TestRunSCPReportsLegacyProtocolAfterFallback(t *testing.T) {
	useMockSCP(t, "#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = \"-O\" ]; then\n    exit 0\n  fi\ndone\necho \"scp: sftp server unavailable: connection failed\" 1>&2\nexit 1\n")

	m := NewManager(t.TempDir(), "bash -lc", 15)
	conn := &model.Connection{Port: 22, ControlPath: filepath.Join(t.TempDir(), "ctrl.sock")}

	res, err := m.runSCP(conn, "", 5, "src.txt", "dst.txt")
	if err != nil {
		t.Fatalf("runSCP unexpected error: %v", err)
	}
	if res.Protocol != transferProtocolSCPLegacy {
		t.Fatalf("unexpected protocol: got=%q want=%q", res.Protocol, transferProtocolSCPLegacy)
	}
	if !res.FallbackUsed {
		t.Fatalf("fallback_used should be true")
	}
	if !strings.Contains(res.FallbackReason, "sftp server unavailable") {
		t.Fatalf("unexpected fallback reason: %q", res.FallbackReason)
	}
}

func TestRunSCPDoesNotFallbackForNonSFTPErrors(t *testing.T) {
	useMockSCP(t, "#!/bin/sh\necho \"Permission denied\" 1>&2\nexit 1\n")

	m := NewManager(t.TempDir(), "bash -lc", 15)
	conn := &model.Connection{Port: 22, ControlPath: filepath.Join(t.TempDir(), "ctrl.sock")}

	res, err := m.runSCP(conn, "", 5, "src.txt", "dst.txt")
	if err == nil {
		t.Fatalf("runSCP should fail for non-retryable errors")
	}
	if res.Protocol != transferProtocolSFTP {
		t.Fatalf("unexpected protocol for first-attempt failure: %q", res.Protocol)
	}
	if res.FallbackUsed {
		t.Fatalf("fallback_used should be false")
	}
	ce, ok := err.(*errorsx.CsshError)
	if !ok || ce.Code != errorsx.CodeInternal {
		t.Fatalf("expected internal cssh error, got %#v", err)
	}
}

func useMockSCP(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "scp")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write mock scp: %v", err)
	}
	oldPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatalf("set PATH: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPath)
	})
}
