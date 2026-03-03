package app

import (
	"path/filepath"
	"strings"
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
	tpl := security.BuildCommandTemplate("mkfs /dev/sdb")
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
		CommandTpl:   tpl,
		CommandHash:  security.HashCommandTemplate(tpl),
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

// TestTokenCollisionRejected verifies that an approval token for one command
// cannot be reused for a different command that happens to produce the same
// template hash (e.g., "mkfs /dev/sda" and "mkfs /dev/sdb" both normalize to
// "mkfs /PATH"). The fix validates the full command, not just the hash.
func TestTokenCollisionRejected(t *testing.T) {
	tmp := t.TempDir()
	svc := newApprovalTestService(t, tmp)

	// Create an approval for "mkfs /dev/sda"
	cmdA := "mkfs /dev/sda"
	cmdB := "mkfs /dev/sdb"
	tplA := security.BuildCommandTemplate(cmdA)
	tplB := security.BuildCommandTemplate(cmdB)
	hashA := security.HashCommandTemplate(tplA)
	hashB := security.HashCommandTemplate(tplB)

	// Confirm the templates collide (the bug scenario)
	if hashA != hashB {
		t.Fatalf("expected template hash collision between %q and %q", cmdA, cmdB)
	}

	// Create and approve a request for cmdA
	approvalID := "apr_collision_1"
	req := model.ApprovalRequest{
		ID:           approvalID,
		CreatedAt:    time.Now().UTC(),
		Status:       model.ApprovalPending,
		Command:      cmdA,
		ConnectionID: "conn_1",
		Host:         "10.0.0.5",
		Username:     "deploy",
		RiskLevel:    model.RiskL2,
		DenyClass:    model.DenyNeedApprove,
		Capability:   "exec_high_risk",
		CommandTpl:   tplA,
		CommandHash:  hashA,
		Reason:       "dangerous command requires approval",
		RequestedBy:  "mcp",
	}
	if err := svc.approvals.Create(req); err != nil {
		t.Fatalf("create approval: %v", err)
	}
	if _, err := svc.approvals.Resolve(approvalID, model.ApprovalApproved, "operator", ""); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Try to use the token with cmdB (different command, same hash) → should be rejected
	_, err := svc.authorizePrivilege("conn_1", "", "exec_high_risk", cmdB, tplB, hashB, model.RiskL2, "dangerous", approvalID, "10.0.0.5", "deploy", false, 0)
	if err == nil {
		t.Fatalf("expected rejection when using token for %q with command %q", cmdA, cmdB)
	}
	if !strings.Contains(err.Error(), "does not match current command") {
		t.Fatalf("expected command mismatch error, got: %v", err)
	}

	// Using the token with cmdA (same command) → should succeed
	authz, err := svc.authorizePrivilege("conn_1", "", "exec_high_risk", cmdA, tplA, hashA, model.RiskL2, "dangerous", approvalID, "10.0.0.5", "deploy", false, 0)
	if err != nil {
		// Token was already consumed by the failed attempt reading it, recreate
		// Actually the failed attempt above read the request but command didn't match,
		// so MarkUsed was never called. Let's verify:
		t.Fatalf("unexpected error: %v", err)
	}
	if !authz.Allowed {
		t.Fatalf("expected allowed for matching command, got not allowed")
	}
}

// TestReusableGrantCaching verifies that after approving a workspace_roots
// violation command (Reusable=true), similar commands auto-approve via the
// cached grant without requiring a new approval token.
func TestReusableGrantCaching(t *testing.T) {
	tmp := t.TempDir()
	svc := newApprovalTestService(t, tmp)

	// Simulate a workspace_roots policy upgrade command
	cmd := "cp /home/user/a.txt /opt/app/"
	policy := security.EvaluateExecPolicyWithProfile(cmd, "L2", false, false, nil, []string{"/home/user"}, "")
	if policy.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for workspace_roots violation, got %s", policy.DenyClass)
	}
	if !policy.Reusable {
		t.Fatalf("expected Reusable=true for workspace_roots upgrade")
	}

	// Create and approve
	approvalID := "apr_reusable_1"
	req := model.ApprovalRequest{
		ID:           approvalID,
		CreatedAt:    time.Now().UTC(),
		Status:       model.ApprovalPending,
		Command:      cmd,
		ConnectionID: "conn_1",
		Host:         "10.0.0.5",
		Username:     "deploy",
		RiskLevel:    policy.RiskLevel,
		DenyClass:    policy.DenyClass,
		Capability:   policy.Capability,
		CommandTpl:   policy.Template,
		CommandHash:  policy.TemplateHash,
		Reason:       policy.Reason,
		RequestedBy:  "mcp",
		Reusable:     true,
	}
	if err := svc.approvals.Create(req); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.approvals.Resolve(approvalID, model.ApprovalApproved, "operator", ""); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Use the token — this should also create a grant
	authz, err := svc.authorizePrivilege("conn_1", "", policy.Capability, cmd, policy.Template, policy.TemplateHash, policy.RiskLevel, policy.Reason, approvalID, "10.0.0.5", "deploy", true, 0)
	if err != nil {
		t.Fatalf("authorize with token: %v", err)
	}
	if !authz.Allowed {
		t.Fatalf("expected allowed")
	}
	if authz.GrantID == "" {
		t.Fatalf("expected a grant to be created for reusable command")
	}

	// Verify session-scoped grant has zero ExpiresAt
	grants, _ := svc.grants.List("conn_1", true)
	if len(grants) == 0 {
		t.Fatalf("expected grant to exist")
	}
	if !grants[0].ExpiresAt.IsZero() {
		t.Fatalf("session-scoped grant should have zero ExpiresAt, got %v", grants[0].ExpiresAt)
	}

	// Now try a similar command (same template) WITHOUT a token — should auto-approve via grant
	cmd2 := "cp /home/user/b.txt /opt/app/"
	policy2 := security.EvaluateExecPolicyWithProfile(cmd2, "L2", false, false, nil, []string{"/home/user"}, "")
	if policy2.TemplateHash != policy.TemplateHash {
		t.Fatalf("expected same template hash for similar commands")
	}

	authz2, err := svc.authorizePrivilege("conn_1", "", policy2.Capability, cmd2, policy2.Template, policy2.TemplateHash, policy2.RiskLevel, policy2.Reason, "", "10.0.0.5", "deploy", true, 0)
	if err != nil {
		t.Fatalf("authorize via grant cache: %v", err)
	}
	if !authz2.Allowed {
		t.Fatalf("expected auto-approve via grant cache")
	}
	if authz2.ConfirmMode != "grant_cache" {
		t.Fatalf("expected confirm_mode=grant_cache, got %q", authz2.ConfirmMode)
	}
}

// TestNonReusableNoCache verifies that dangerous pattern-matched commands
// (Reusable=false) never get grant caching — each execution requires a
// fresh approval token even if the template hash matches.
func TestNonReusableNoCache(t *testing.T) {
	tmp := t.TempDir()
	svc := newApprovalTestService(t, tmp)

	cmd := "mkfs /dev/sda"
	policy := security.EvaluateExecPolicyWithProfile(cmd, "L2", false, false, nil, nil, "")
	if policy.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove, got %s", policy.DenyClass)
	}
	if policy.Reusable {
		t.Fatalf("expected Reusable=false for dangerous pattern match")
	}

	// Create and approve
	approvalID := "apr_nonreuse_1"
	req := model.ApprovalRequest{
		ID:           approvalID,
		CreatedAt:    time.Now().UTC(),
		Status:       model.ApprovalPending,
		Command:      cmd,
		ConnectionID: "conn_1",
		Host:         "10.0.0.5",
		Username:     "deploy",
		RiskLevel:    policy.RiskLevel,
		DenyClass:    policy.DenyClass,
		Capability:   policy.Capability,
		CommandTpl:   policy.Template,
		CommandHash:  policy.TemplateHash,
		Reason:       policy.Reason,
		RequestedBy:  "mcp",
		Reusable:     false,
	}
	if err := svc.approvals.Create(req); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.approvals.Resolve(approvalID, model.ApprovalApproved, "operator", ""); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Consume the token with reusable=false → should NOT create a grant
	authz, err := svc.authorizePrivilege("conn_1", "", policy.Capability, cmd, policy.Template, policy.TemplateHash, policy.RiskLevel, policy.Reason, approvalID, "10.0.0.5", "deploy", false, 0)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !authz.Allowed {
		t.Fatalf("expected allowed")
	}
	if authz.GrantID != "" {
		t.Fatalf("expected no grant for non-reusable command, got %q", authz.GrantID)
	}

	// Try mkfs /dev/sdb without a token — should require new approval (no grant cache)
	cmd2 := "mkfs /dev/sdb"
	policy2 := security.EvaluateExecPolicyWithProfile(cmd2, "L2", false, false, nil, nil, "")
	authz2, err := svc.authorizePrivilege("conn_1", "", policy2.Capability, cmd2, policy2.Template, policy2.TemplateHash, policy2.RiskLevel, policy2.Reason, "", "10.0.0.5", "deploy", false, 0)
	if err != nil {
		t.Fatalf("authorize2: %v", err)
	}
	if authz2.Allowed {
		t.Fatalf("expected NOT allowed — non-reusable command should not auto-approve")
	}
	statusVal, ok := authz2.StatusResp["status"]
	if !ok || statusVal != "approval_required" {
		t.Fatalf("expected approval_required status, got %v", authz2.StatusResp)
	}
}

// newApprovalTestService creates a minimal Service for testing authorizePrivilege.
func newApprovalTestService(t *testing.T, tmp string) *Service {
	t.Helper()
	return NewService(model.Config{
		DefaultShell:      "bash -lc",
		DefaultTimeoutSec: 120,
		RuntimeDir:        filepath.Join(tmp, "runtime"),
		LogsDir:           filepath.Join(tmp, "logs"),
		ProfilesFile:      filepath.Join(tmp, "profiles.json"),
	})
}

// helpers that call the security package without importing it directly
// (we're in the app package, which already imports security)

func classifyForTest(cmd string) model.DenyClass {
	p := security.EvaluateExecPolicyWithProfile(cmd, "L2", false, false, nil, nil, "")
	return p.DenyClass
}

func classifyForTestWithOverrides(cmd string, allowReboot, allowDiskOps bool) model.DenyClass {
	p := security.EvaluateExecPolicyWithProfile(cmd, "L2", allowReboot, allowDiskOps, nil, nil, "")
	return p.DenyClass
}

// TestGrantWithTTL verifies that a grant created with a positive TTL has a
// non-zero ExpiresAt approximately TTL seconds in the future.
func TestGrantWithTTL(t *testing.T) {
	tmp := t.TempDir()
	svc := newApprovalTestService(t, tmp)

	cmd := "cp /home/user/a.txt /opt/app/"
	policy := security.EvaluateExecPolicyWithProfile(cmd, "L2", false, false, nil, []string{"/home/user"}, "")

	approvalID := "apr_ttl_1"
	req := model.ApprovalRequest{
		ID:           approvalID,
		CreatedAt:    time.Now().UTC(),
		Status:       model.ApprovalPending,
		Command:      cmd,
		ConnectionID: "conn_1",
		Host:         "10.0.0.5",
		Username:     "deploy",
		RiskLevel:    policy.RiskLevel,
		DenyClass:    policy.DenyClass,
		Capability:   policy.Capability,
		CommandTpl:   policy.Template,
		CommandHash:  policy.TemplateHash,
		Reason:       policy.Reason,
		RequestedBy:  "mcp",
		Reusable:     true,
	}
	if err := svc.approvals.Create(req); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.approvals.Resolve(approvalID, model.ApprovalApproved, "operator", ""); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	before := time.Now().UTC()
	authz, err := svc.authorizePrivilege("conn_1", "", policy.Capability, cmd, policy.Template, policy.TemplateHash, policy.RiskLevel, policy.Reason, approvalID, "10.0.0.5", "deploy", true, 300)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !authz.Allowed || authz.GrantID == "" {
		t.Fatalf("expected allowed with grant")
	}

	grants, _ := svc.grants.List("conn_1", true)
	if len(grants) == 0 {
		t.Fatalf("expected grant to exist")
	}
	g := grants[0]
	if g.ExpiresAt.IsZero() {
		t.Fatalf("TTL grant should have non-zero ExpiresAt")
	}
	expectedMin := before.Add(300 * time.Second)
	expectedMax := before.Add(301 * time.Second)
	if g.ExpiresAt.Before(expectedMin) || g.ExpiresAt.After(expectedMax) {
		t.Fatalf("ExpiresAt should be ~300s from now, got %v (expected between %v and %v)", g.ExpiresAt, expectedMin, expectedMax)
	}
}

// TestSessionScopedGrantSurvivesLong verifies that a session-scoped grant
// (TTL=0) does not expire by time — it only dies when the connection disconnects.
func TestSessionScopedGrantSurvivesLong(t *testing.T) {
	tmp := t.TempDir()
	svc := newApprovalTestService(t, tmp)

	cmd := "cp /home/user/a.txt /opt/app/"
	policy := security.EvaluateExecPolicyWithProfile(cmd, "L2", false, false, nil, []string{"/home/user"}, "")

	approvalID := "apr_session_1"
	req := model.ApprovalRequest{
		ID:           approvalID,
		CreatedAt:    time.Now().UTC(),
		Status:       model.ApprovalPending,
		Command:      cmd,
		ConnectionID: "conn_1",
		Host:         "10.0.0.5",
		Username:     "deploy",
		RiskLevel:    policy.RiskLevel,
		DenyClass:    policy.DenyClass,
		Capability:   policy.Capability,
		CommandTpl:   policy.Template,
		CommandHash:  policy.TemplateHash,
		Reason:       policy.Reason,
		RequestedBy:  "mcp",
		Reusable:     true,
	}
	if err := svc.approvals.Create(req); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.approvals.Resolve(approvalID, model.ApprovalApproved, "operator", ""); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Create session-scoped grant (TTL=0)
	authz, err := svc.authorizePrivilege("conn_1", "", policy.Capability, cmd, policy.Template, policy.TemplateHash, policy.RiskLevel, policy.Reason, approvalID, "10.0.0.5", "deploy", true, 0)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !authz.Allowed || authz.GrantID == "" {
		t.Fatalf("expected allowed with grant")
	}

	// FindActive well past 15 minutes should still return the grant
	futureTime := time.Now().UTC().Add(2 * time.Hour)
	grant, err := svc.grants.FindActive("conn_1", policy.Capability, policy.TemplateHash, futureTime)
	if err != nil {
		t.Fatalf("FindActive: %v", err)
	}
	if grant == nil {
		t.Fatalf("session-scoped grant should survive well past 15 minutes")
	}

	// RevokeByConnection should clean it up
	svc.grants.RevokeByConnection("conn_1")
	grant2, err := svc.grants.FindActive("conn_1", policy.Capability, policy.TemplateHash, futureTime)
	if err != nil {
		t.Fatalf("FindActive after revoke: %v", err)
	}
	if grant2 != nil {
		t.Fatalf("grant should be revoked after RevokeByConnection")
	}
}
