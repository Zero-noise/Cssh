package approvals

import (
	"path/filepath"
	"testing"
	"time"

	"cssh/internal/model"
)

func TestGrantStoreLifecycle(t *testing.T) {
	tmp := t.TempDir()
	s := NewGrantStore(filepath.Join(tmp, "grants.json"))
	now := time.Now().UTC()
	g := model.PrivilegeGrant{
		ID:           "grt_1",
		CreatedAt:    now,
		ExpiresAt:    now.Add(10 * time.Minute),
		Status:       model.PrivilegeGrantActive,
		ConnectionID: "conn_1",
		Capability:   "sudo_exec",
		CommandHash:  "abc",
		RiskLevel:    model.RiskL2,
		ApprovedBy:   "alice",
	}
	if err := s.Create(g); err != nil {
		t.Fatalf("create: %v", err)
	}
	found, err := s.FindActive("conn_1", "sudo_exec", "abc", now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("find active: %v", err)
	}
	if found == nil || found.ID != "grt_1" {
		t.Fatalf("unexpected found grant: %#v", found)
	}
	got, err := s.Revoke("grt_1")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got == nil || got.Status != model.PrivilegeGrantRevoked {
		t.Fatalf("unexpected revoke status: %#v", got)
	}
}
