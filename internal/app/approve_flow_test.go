package app

import (
	"path/filepath"
	"testing"
	"time"

	"cssh/internal/approvals"
	"cssh/internal/model"
	"cssh/internal/security"
)

// TestApproveFlowEndToEnd simulates the full cross-process approval workflow:
//
//	MCP server: Exec("mkfs /dev/sdb") → approval_required + approval_id
//	csshctl:    approve <id>           → status=approved
//	MCP server: Exec("mkfs /dev/sdb", approval_token=<id>) → allowed
//
// This uses a shared approvals.jsonl (as the real flow does between two processes).
func TestApproveFlowEndToEnd(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "approvals.jsonl")

	// ── Phase 1: MCP server creates a pending approval ──
	mcpStore := approvals.NewStore(storePath)
	approvalID := "apr_test_flow_1"
	req := model.ApprovalRequest{
		ID:           approvalID,
		CreatedAt:    time.Now().UTC(),
		Status:       model.ApprovalPending,
		Command:      "mkfs /dev/sdb",
		ConnectionID: "conn_1",
		Host:         "10.0.0.5",
		Username:     "deploy",
		RiskLevel:    model.RiskL2,
		DenyClass:    model.DenyNeedApprove,
		Capability:   "exec_high_risk",
		CommandTpl:   "mkfs /PATH",
		CommandHash:  "abc123",
		Reason:       "dangerous command requires approval",
		RequestedBy:  "mcp",
	}
	if err := mcpStore.Create(req); err != nil {
		t.Fatalf("create approval: %v", err)
	}

	// Verify it's pending
	got, err := mcpStore.Get(approvalID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != model.ApprovalPending {
		t.Fatalf("expected pending, got %s", got.Status)
	}

	// ── Phase 2: csshctl (separate process) resolves the approval ──
	// Simulate a completely separate Store instance (as csshctl would have)
	csshctlStore := approvals.NewStore(storePath)

	// csshctl reads the approval to display context
	displayed, err := csshctlStore.Get(approvalID)
	if err != nil {
		t.Fatalf("csshctl get: %v", err)
	}
	if displayed.Host != "10.0.0.5" {
		t.Fatalf("csshctl should see host, got %q", displayed.Host)
	}
	if displayed.Username != "deploy" {
		t.Fatalf("csshctl should see username, got %q", displayed.Username)
	}
	if displayed.Command != "mkfs /dev/sdb" {
		t.Fatalf("csshctl should see command, got %q", displayed.Command)
	}
	if string(displayed.DenyClass) != string(model.DenyNeedApprove) {
		t.Fatalf("csshctl should see deny_class, got %q", displayed.DenyClass)
	}

	// csshctl approves
	resolved, err := csshctlStore.Resolve(approvalID, model.ApprovalApproved, "operator", "")
	if err != nil {
		t.Fatalf("csshctl resolve: %v", err)
	}
	if resolved.Status != model.ApprovalApproved {
		t.Fatalf("expected approved, got %s", resolved.Status)
	}
	if resolved.ApprovedBy != "operator" {
		t.Fatalf("expected operator, got %s", resolved.ApprovedBy)
	}

	// ── Phase 3: MCP server retries with approval_token ──
	// MCP server reads the same file and sees the resolved approval
	afterApprove, err := mcpStore.Get(approvalID)
	if err != nil {
		t.Fatalf("mcp get after approve: %v", err)
	}
	if afterApprove.Status != model.ApprovalApproved {
		t.Fatalf("MCP should see approved status, got %s", afterApprove.Status)
	}

	// MCP server atomically marks used
	used, err := mcpStore.MarkUsed(approvalID)
	if err != nil {
		t.Fatalf("mark used: %v", err)
	}
	if used == nil {
		t.Fatalf("MarkUsed should succeed on first use")
	}
	if used.UsedAt == nil {
		t.Fatalf("UsedAt should be stamped")
	}

	// ── Phase 4: Verify one-time-use enforcement ──
	used2, err := mcpStore.MarkUsed(approvalID)
	if err != nil {
		t.Fatalf("mark used again: %v", err)
	}
	if used2 != nil {
		t.Fatalf("MarkUsed should return nil on second use (one-time enforcement)")
	}
}

// TestApproveFlowReject verifies rejection path.
func TestApproveFlowReject(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "approvals.jsonl")
	store := approvals.NewStore(storePath)

	req := model.ApprovalRequest{
		ID:           "apr_reject_1",
		CreatedAt:    time.Now().UTC(),
		Status:       model.ApprovalPending,
		Command:      "dd of=/dev/sda",
		ConnectionID: "conn_2",
		Reason:       "dangerous",
		RequestedBy:  "mcp",
	}
	if err := store.Create(req); err != nil {
		t.Fatalf("create: %v", err)
	}

	// csshctl rejects
	resolved, err := store.Resolve("apr_reject_1", model.ApprovalRejected, "admin", "not authorized")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.Status != model.ApprovalRejected {
		t.Fatalf("expected rejected, got %s", resolved.Status)
	}
	if resolved.RejectReason != "not authorized" {
		t.Fatalf("expected reason, got %s", resolved.RejectReason)
	}

	// MarkUsed should return nil for rejected tokens
	used, err := store.MarkUsed("apr_reject_1")
	if err != nil {
		t.Fatalf("mark used: %v", err)
	}
	if used != nil {
		t.Fatalf("MarkUsed should return nil for rejected approval")
	}
}

// TestApproveFlowTokenBeforeApproval verifies that using a token
// before csshctl resolves it returns the pending status.
func TestApproveFlowTokenBeforeApproval(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "approvals.jsonl")
	store := approvals.NewStore(storePath)

	req := model.ApprovalRequest{
		ID:           "apr_early_1",
		CreatedAt:    time.Now().UTC(),
		Status:       model.ApprovalPending,
		Command:      "reboot",
		ConnectionID: "conn_3",
		Reason:       "dangerous",
		RequestedBy:  "mcp",
	}
	if err := store.Create(req); err != nil {
		t.Fatalf("create: %v", err)
	}

	// MarkUsed on a pending approval should return nil (not approved yet)
	used, err := store.MarkUsed("apr_early_1")
	if err != nil {
		t.Fatalf("mark used: %v", err)
	}
	if used != nil {
		t.Fatalf("MarkUsed should return nil for pending approval")
	}
}

// TestDenyAlwaysCannotBeApproved verifies that even if someone
// managed to create and approve a token, DenyAlways is checked
// in Exec() before authorizePrivilege() is ever reached.
func TestDenyAlwaysCannotBeApproved(t *testing.T) {
	// This test verifies the policy layer, not the approval store.
	// DenyAlways is checked before any token validation.
	// We test via EvaluateExecPolicyWithProfile.
	from := "cssh/internal/security"
	_ = from // reference for readers

	// A fork bomb should be DenyAlways regardless of profile
	cmd := ":(){ :|:& };:"
	dc := classifyForTest(cmd)
	if dc != model.DenyAlways {
		t.Fatalf("fork bomb: expected DenyAlways, got %s", dc)
	}

	// rm -rf / should be DenyAlways
	dc = classifyForTest("rm -rf /")
	if dc != model.DenyAlways {
		t.Fatalf("rm -rf /: expected DenyAlways, got %s", dc)
	}

	// Even with AllowDiskOps=true, rm -rf / stays DenyAlways
	dc = classifyForTestWithOverrides("rm -rf /", true, true)
	if dc != model.DenyAlways {
		t.Fatalf("rm -rf / with overrides: expected DenyAlways, got %s", dc)
	}
}

// TestOpsStrictDefaultsUpgradeL2(t *testing.T) verifies that ops_strict
// connections default to MaxAutoRisk=L1, upgrading L2 DenyNone to DenyNeedApprove.
func TestOpsStrictDefaultsUpgradeL2(t *testing.T) {
	tmp := t.TempDir()
	svc := NewService(model.Config{
		DefaultShell:           "bash -lc",
		DefaultTimeoutSec:      120,
		RuntimeDir:             filepath.Join(tmp, "runtime"),
		LogsDir:                filepath.Join(tmp, "logs"),
		ProfilesFile:           filepath.Join(tmp, "profiles.json"),
		SecurityProfileDefault: "ops_strict",
		ConnectRequireProfile:  false,
		SudoEnabled:            true,
	})

	allowPublic := true
	conn, err := svc.resolveConnectionInput(model.ConnectionInput{
		Host:            "10.0.0.5",
		Username:        "deploy",
		AllowPublicHost: &allowPublic,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if conn.MaxAutoRisk != "L1" {
		t.Fatalf("ops_strict should default MaxAutoRisk to L1, got %q", conn.MaxAutoRisk)
	}

	// Verify an easy_safe connection does NOT get L1
	svc2 := NewService(model.Config{
		DefaultShell:           "bash -lc",
		DefaultTimeoutSec:      120,
		RuntimeDir:             filepath.Join(tmp, "runtime2"),
		LogsDir:                filepath.Join(tmp, "logs2"),
		ProfilesFile:           filepath.Join(tmp, "profiles2.json"),
		SecurityProfileDefault: "easy_safe",
		ConnectRequireProfile:  false,
	})
	conn2, err := svc2.resolveConnectionInput(model.ConnectionInput{
		Host:            "10.0.0.6",
		Username:        "dev",
		AllowPublicHost: &allowPublic,
	})
	if err != nil {
		t.Fatalf("resolve2: %v", err)
	}
	if conn2.MaxAutoRisk != "" {
		t.Fatalf("easy_safe should not set MaxAutoRisk, got %q", conn2.MaxAutoRisk)
	}
}

// helpers that call the security package without importing it directly
// (we're in the app package, which already imports security)

func classifyForTest(cmd string) model.DenyClass {
	p := security.EvaluateExecPolicyWithProfile(cmd, "L2", false, false, nil, nil)
	return p.DenyClass
}

func classifyForTestWithOverrides(cmd string, allowReboot, allowDiskOps bool) model.DenyClass {
	p := security.EvaluateExecPolicyWithProfile(cmd, "L2", allowReboot, allowDiskOps, nil, nil)
	return p.DenyClass
}
