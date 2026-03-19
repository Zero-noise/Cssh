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

	res, err := m.runSCP(conn, "", 5, false, nil, "src.txt", "dst.txt")
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

	res, err := m.runSCP(conn, "", 5, false, nil, "src.txt", "dst.txt")
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

	res, err := m.runSCP(conn, "", 5, false, nil, "src.txt", "dst.txt")
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

func TestRunSCPRecursive_SFTPSuccess(t *testing.T) {
	// Mock scp that succeeds and verifies -r flag is present
	useMockSCP(t, "#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = \"-r\" ]; then\n    exit 0\n  fi\ndone\necho \"missing -r flag\" 1>&2\nexit 1\n")

	m := NewManager(t.TempDir(), "bash -lc", 15)
	conn := &model.Connection{Port: 22, ControlPath: filepath.Join(t.TempDir(), "ctrl.sock")}

	res, err := m.runSCP(conn, "", 5, true, nil, "srcdir", "dstdir")
	if err != nil {
		t.Fatalf("runSCP recursive unexpected error: %v", err)
	}
	if res.Protocol != transferProtocolSFTP {
		t.Fatalf("unexpected protocol: got=%q want=%q", res.Protocol, transferProtocolSFTP)
	}
}

func TestRunSCPRecursive_LegacyFallback(t *testing.T) {
	// Mock scp: SFTP fails with sftp error, legacy with -O and -r succeeds
	useMockSCP(t, "#!/bin/sh\nhas_O=false\nhas_r=false\nfor arg in \"$@\"; do\n  if [ \"$arg\" = \"-O\" ]; then has_O=true; fi\n  if [ \"$arg\" = \"-r\" ]; then has_r=true; fi\ndone\nif [ \"$has_O\" = \"true\" ] && [ \"$has_r\" = \"true\" ]; then\n  exit 0\nfi\necho \"scp: sftp server unavailable\" 1>&2\nexit 1\n")

	m := NewManager(t.TempDir(), "bash -lc", 15)
	conn := &model.Connection{Port: 22, ControlPath: filepath.Join(t.TempDir(), "ctrl.sock")}

	res, err := m.runSCP(conn, "", 5, true, nil, "srcdir", "dstdir")
	if err != nil {
		t.Fatalf("runSCP recursive fallback unexpected error: %v", err)
	}
	if res.Protocol != transferProtocolSCPLegacy {
		t.Fatalf("unexpected protocol: got=%q want=%q", res.Protocol, transferProtocolSCPLegacy)
	}
	if !res.FallbackUsed {
		t.Fatalf("fallback_used should be true")
	}
}

func TestRunSCPProgressCallback(t *testing.T) {
	useMockSCP(t, "#!/bin/sh\necho 'progress line' 1>&2\nexit 0\n")

	m := NewManager(t.TempDir(), "bash -lc", 15)
	conn := &model.Connection{Port: 22, ControlPath: filepath.Join(t.TempDir(), "ctrl.sock")}

	var chunks []string
	onProgress := func(p ExecProgress) {
		chunks = append(chunks, p.Chunk)
	}
	_, err := m.runSCP(conn, "", 5, false, onProgress, "src.txt", "dst.txt")
	if err != nil {
		t.Fatalf("runSCP unexpected error: %v", err)
	}
	if len(chunks) == 0 {
		t.Fatalf("expected progress callback to be called at least once")
	}
	combined := strings.Join(chunks, "")
	if !strings.Contains(combined, "progress line") {
		t.Fatalf("progress callback should contain stderr output, got: %q", combined)
	}
}

func TestBuildRsyncArgs(t *testing.T) {
	args := buildRsyncArgs("ssh -p 22", "src", "dst")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--partial") {
		t.Fatalf("rsync args should include --partial: %q", joined)
	}
	if strings.Contains(joined, "--info=stats2") {
		t.Fatalf("rsync args should not include --info=stats2: %q", joined)
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
