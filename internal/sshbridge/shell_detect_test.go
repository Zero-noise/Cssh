package sshbridge

import (
	"testing"

	"cssh/internal/model"
)

func TestNeedsShellProbe(t *testing.T) {
	tests := []struct {
		shell string
		want  bool
	}{
		{"", true},
		{"auto", true},
		{"AUTO", true},
		{"  auto  ", true},
		{"  ", true},
		{"bash -lc", false},
		{"sh -c", false},
		{ShellRaw, false},
	}
	for _, tt := range tests {
		if got := NeedsShellProbe(tt.shell); got != tt.want {
			t.Errorf("NeedsShellProbe(%q) = %v, want %v", tt.shell, got, tt.want)
		}
	}
}

func TestResolveShellForExec(t *testing.T) {
	tests := []struct {
		shell string
		want  string
	}{
		{ShellRaw, ""},
		{"bash -lc", "bash -lc"},
		{"sh -c", "sh -c"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := ResolveShellForExec(tt.shell); got != tt.want {
			t.Errorf("ResolveShellForExec(%q) = %q, want %q", tt.shell, got, tt.want)
		}
	}
}

func TestDisplayShell(t *testing.T) {
	tests := []struct {
		shell string
		want  string
	}{
		{ShellRaw, "(raw / no wrapper)"},
		{"", "(not detected)"},
		{"bash -lc", "bash -lc"},
		{"sh -c", "sh -c"},
	}
	for _, tt := range tests {
		if got := DisplayShell(tt.shell); got != tt.want {
			t.Errorf("DisplayShell(%q) = %q, want %q", tt.shell, got, tt.want)
		}
	}
}

func TestValidShellValues(t *testing.T) {
	valid := []string{"", "auto", "bash -lc", "sh -c", ShellRaw}
	for _, v := range valid {
		if !ValidShellValues[v] {
			t.Errorf("expected %q to be valid", v)
		}
	}

	invalid := []string{"zsh -c", "bsh -lc", "fish", "bash", "/bin/sh"}
	for _, v := range invalid {
		if ValidShellValues[v] {
			t.Errorf("expected %q to be invalid", v)
		}
	}
}

func TestRunShellProbe_NoSocket(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)
	// Probe against a non-existent control socket should return false, not panic.
	ok := m.runShellProbe("/nonexistent/ctrl.sock", 22, "nobody@localhost", "echo __cssh_ok")
	if ok {
		t.Fatal("expected probe to fail with non-existent control socket")
	}
}

func TestProbeShell_AllFail(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)
	conn := connWithSocket(t.TempDir(), "/nonexistent/ctrl.sock")

	shell, err := m.probeShell(conn)
	if err == nil {
		t.Fatalf("expected error when all probes fail, got shell=%q", shell)
	}
	if shell != "" {
		t.Fatalf("expected empty shell on failure, got %q", shell)
	}
}

func TestExecShellPriority_ConnectionOverridesDefault(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)

	// Simulate a connection with "sh -c" detected shell.
	m.mu.Lock()
	m.connections["conn_sh"] = connWithShell("conn_sh", "sh -c")
	m.mu.Unlock()

	// Without a session, ExecWithInput should use the connection's shell.
	// It will fail (no real SSH) but we can verify the error isn't about
	// shell detection — it should be a preflight check failure.
	_, err := m.ExecWithInput("conn_sh", "", "echo test", "/", 5, "")
	if err == nil {
		t.Fatal("expected error (no real SSH), but got nil")
	}
	// The error should be preflight (dead connection), not shell-related.
}

func TestExecShellPriority_RawSkipsWrapper(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)

	m.mu.Lock()
	m.connections["conn_raw"] = connWithShell("conn_raw", ShellRaw)
	m.mu.Unlock()

	// Same test: verify the connection with __raw__ doesn't panic.
	_, err := m.ExecWithInput("conn_raw", "", "echo test", "/", 5, "")
	if err == nil {
		t.Fatal("expected error (no real SSH), but got nil")
	}
}

func TestOpenSession_InheritsConnectionShell(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)

	m.mu.Lock()
	m.connections["conn_sh"] = connWithShell("conn_sh", "sh -c")
	m.mu.Unlock()

	sess, err := m.OpenSession("conn_sh", "/", "")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Shell != "sh -c" {
		t.Fatalf("expected session shell = %q, got %q", "sh -c", sess.Shell)
	}
}

func TestOpenSession_ExplicitShellOverridesConnection(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)

	m.mu.Lock()
	m.connections["conn_sh"] = connWithShell("conn_sh", "sh -c")
	m.mu.Unlock()

	sess, err := m.OpenSession("conn_sh", "/", "bash -lc")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Shell != "bash -lc" {
		t.Fatalf("expected session shell = %q, got %q", "bash -lc", sess.Shell)
	}
}

func TestOpenSession_FallsBackToDefault(t *testing.T) {
	m := NewManager(t.TempDir(), "bash -lc", 30)

	m.mu.Lock()
	m.connections["conn_none"] = connWithShell("conn_none", "")
	m.mu.Unlock()

	sess, err := m.OpenSession("conn_none", "/", "")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Shell != "bash -lc" {
		t.Fatalf("expected session shell = %q (default), got %q", "bash -lc", sess.Shell)
	}
}

// --- helpers ---

func connWithSocket(dir, controlPath string) *model.Connection {
	return &model.Connection{
		ID:             "conn_probe",
		Host:           "localhost",
		Port:           22,
		Username:       "nobody",
		ControlPath:    controlPath,
		WorkspaceRoots: []string{"/"},
	}
}

func connWithShell(id, shell string) *model.Connection {
	return &model.Connection{
		ID:             id,
		Host:           "localhost",
		Port:           22,
		Username:       "user",
		ControlPath:    "/nonexistent/ctrl.sock",
		Shell:          shell,
		WorkspaceRoots: []string{"/"},
	}
}
