package approvals

import (
	"path/filepath"
	"testing"
	"time"

	"cssh/internal/model"
)

func TestApprovalStoreLifecycle(t *testing.T) {
	tmp := t.TempDir()
	s := NewStore(filepath.Join(tmp, "approvals.jsonl"))
	req := model.ApprovalRequest{
		ID:           "apr_1",
		CreatedAt:    time.Now().UTC(),
		Status:       model.ApprovalPending,
		Command:      "rm -rf /tmp/abc",
		ConnectionID: "conn_1",
		RiskLevel:    model.RiskL2,
		Reason:       "test",
		RequestedBy:  "mcp",
	}
	if err := s.Create(req); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get("apr_1")
	if err != nil || got == nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != model.ApprovalPending {
		t.Fatalf("unexpected status: %s", got.Status)
	}
	updated, err := s.Resolve("apr_1", model.ApprovalApproved, "alice", "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if updated.Status != model.ApprovalApproved {
		t.Fatalf("resolve status: %s", updated.Status)
	}
}
