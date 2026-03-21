package app

import (
	"testing"

	"cssh/internal/model"
)

func TestResolveSessionCWDRejectsDefaultRootOutsideWorkspace(t *testing.T) {
	svc := newApprovalTestService(t, t.TempDir())
	conn := &model.Connection{
		ID:             "conn_1",
		WorkspaceRoots: []string{"/opt/app"},
	}

	if _, err := svc.resolveSessionCWD(conn, ""); err == nil {
		t.Fatal("expected empty session cwd to resolve to / and be rejected outside workspace_roots")
	}

	cwd, err := svc.resolveSessionCWD(conn, "/opt/app/sub")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cwd != "/opt/app/sub" {
		t.Fatalf("unexpected cwd: %q", cwd)
	}
}

func TestResolveEffectiveExecCWDDefaultsToRoot(t *testing.T) {
	svc := newApprovalTestService(t, t.TempDir())
	conn := &model.Connection{
		ID:             "conn_1",
		WorkspaceRoots: []string{"/"},
	}

	cwd, err := svc.resolveEffectiveExecCWD(conn, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cwd != "/" {
		t.Fatalf("expected default effective cwd /, got %q", cwd)
	}
}
