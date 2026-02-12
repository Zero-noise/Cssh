package sshbridge

import (
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
