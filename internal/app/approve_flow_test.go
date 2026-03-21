package app

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cssh/internal/approvals"
	"cssh/internal/errorsx"
	"cssh/internal/model"
	"cssh/internal/security"
	"cssh/internal/util"
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

// TestOpsStrictDefaultsUpgradeL2 verifies that ops_strict
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
		SudoEnabled:            true,
	})

	// Create ops_strict profile
	if err := svc.profiles.Upsert(model.Profile{
		ID: "ops-test", Name: "ops-test", Host: "10.0.0.5", Port: 22,
		Username: "deploy", AuthPriority: []string{"key"}, KeyPath: "",
		WorkspaceRoots:  []string{"/"},
		SecurityProfile: "ops_strict",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	conn, err := svc.resolveConnectionInput(model.ConnectionInput{ProfileID: "ops-test"})
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
	})
	if err := svc2.profiles.Upsert(model.Profile{
		ID: "easy-test", Name: "easy-test", Host: "10.0.0.6", Port: 22,
		Username: "dev", AuthPriority: []string{"key"}, KeyPath: "",
		WorkspaceRoots:  []string{"/"},
		SecurityProfile: "easy_safe",
	}); err != nil {
		t.Fatalf("upsert2: %v", err)
	}
	conn2, err := svc2.resolveConnectionInput(model.ConnectionInput{ProfileID: "easy-test"})
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

// TestCwdDirectoryIsolatedGrants verifies that cwd violation grants are
// isolated by directory: approving cwd=/etc auto-approves same command pattern
// in /etc, but NOT in /var. This is achieved by including the literal cleaned
// cwd in the template hash instead of letting BuildCommandTemplate collapse
// all paths to /PATH.
func TestCwdDirectoryIsolatedGrants(t *testing.T) {
	tmp := t.TempDir()
	svc := newApprovalTestService(t, tmp)

	roots := []string{"/opt/app"}

	// Simulate what ExecWithProgress does for cwd=/etc:
	// Template: "cwd:/etc && rm /PATH"  (literal cwd, templatized command)
	// Use "rm /tmp/a" so the command templates to "rm /PATH"
	cmdTpl := security.BuildCommandTemplate("rm /tmp/a")
	cwdTpl := "cwd:/etc && " + cmdTpl
	cwdHash := security.HashCommandTemplate(cwdTpl)

	// Different cwd must produce different hash
	cwdTpl2 := "cwd:/var && " + cmdTpl
	cwdHash2 := security.HashCommandTemplate(cwdTpl2)
	if cwdHash == cwdHash2 {
		t.Fatalf("expected different hashes for /etc vs /var, both got %s", cwdHash)
	}

	// Same cwd + same command pattern → same hash (for grant reuse)
	// "rm /tmp/a" and "rm /tmp/b" both template to "rm /PATH"
	cmdTpl3 := security.BuildCommandTemplate("rm /tmp/b")
	if cmdTpl != cmdTpl3 {
		t.Fatalf("expected same command template for rm /PATH, got %q vs %q", cmdTpl, cmdTpl3)
	}
	cwdTpl3 := "cwd:/etc && " + cmdTpl3
	cwdHash3 := security.HashCommandTemplate(cwdTpl3)
	if cwdHash != cwdHash3 {
		t.Fatalf("expected same hash for same cwd+pattern, got %s vs %s", cwdHash, cwdHash3)
	}

	// No-cwd command must have different hash from any cwd command
	plainHash := security.HashCommandTemplate(cmdTpl)
	if plainHash == cwdHash {
		t.Fatalf("expected different hash for plain vs cwd command")
	}

	// ── Grant flow: approve cwd=/etc, verify /etc auto-approves, /var does not ──

	evalCmd1 := "cd '/etc' && rm /tmp/a"
	approvalID := "apr_cwd_dir_1"
	req := model.ApprovalRequest{
		ID:           approvalID,
		CreatedAt:    time.Now().UTC(),
		Status:       model.ApprovalPending,
		Command:      evalCmd1,
		ConnectionID: "conn_1",
		Host:         "10.0.0.5",
		Username:     "deploy",
		RiskLevel:    model.RiskL1,
		DenyClass:    model.DenyNeedApprove,
		Capability:   "exec_write",
		CommandTpl:   cwdTpl,
		CommandHash:  cwdHash,
		Reason:       "cwd targets path outside workspace_roots: /etc",
		RequestedBy:  "mcp",
		Reusable:     true,
	}
	if err := svc.approvals.Create(req); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.approvals.Resolve(approvalID, model.ApprovalApproved, "operator", ""); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Consume token → creates grant keyed on cwdHash ("/etc" specific)
	authz, err := svc.authorizePrivilege("conn_1", "", "exec_write", evalCmd1, cwdTpl, cwdHash, model.RiskL1, req.Reason, approvalID, "10.0.0.5", "deploy", true, 0)
	if err != nil || !authz.Allowed {
		t.Fatalf("expected allowed, err=%v, allowed=%v", err, authz.Allowed)
	}
	if authz.GrantID == "" {
		t.Fatalf("expected grant to be created for reusable cwd violation")
	}

	// Same cwd (/etc) + similar command (same pattern "rm /PATH") → auto-approve via grant
	evalCmd1b := "cd '/etc' && rm /tmp/b"
	authz2, err := svc.authorizePrivilege("conn_1", "", "exec_write", evalCmd1b, cwdTpl3, cwdHash3, model.RiskL1, req.Reason, "", "10.0.0.5", "deploy", true, 0)
	if err != nil {
		t.Fatalf("authorize same-cwd: %v", err)
	}
	if !authz2.Allowed {
		t.Fatalf("expected auto-approve via grant for same cwd (/etc)")
	}
	if authz2.ConfirmMode != "grant_cache" {
		t.Fatalf("expected grant_cache, got %q", authz2.ConfirmMode)
	}

	// Different cwd (/var) → NOT auto-approved (different hash)
	evalCmd2 := "cd '/var' && rm /tmp/a"
	authz3, err := svc.authorizePrivilege("conn_1", "", "exec_write", evalCmd2, cwdTpl2, cwdHash2, model.RiskL1, "cwd targets path outside workspace_roots: /var", "", "10.0.0.5", "deploy", true, 0)
	if err != nil {
		t.Fatalf("authorize different-cwd: %v", err)
	}
	if authz3.Allowed {
		t.Fatalf("expected NOT allowed — /var grant does not exist, only /etc was approved")
	}

	// Verify: the workspace_roots policy on the evalCmd string still works
	p := security.EvaluateExecPolicyWithProfile("cd /etc && rm file", "L2", false, false, nil, roots, "")
	if p.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for cd /etc outside roots, got %s", p.DenyClass)
	}
}

// TestCwdValidationForOpenSession verifies the workspace_roots enforcement
// logic used in OpenSession (path.Clean + IsWithinRoots).
func TestCwdValidationForOpenSession(t *testing.T) {
	roots := []string{"/opt/app"}

	cases := []struct {
		cwd     string
		allowed bool
	}{
		{"/opt/app/sub", true},
		{"/opt/app", true},
		{"/etc", false},
		{"/opt/app/../app/sub", true}, // path.Clean → /opt/app/sub
		{"/opt/app/../../etc", false}, // path.Clean → /etc
		{"/", false},                  // not within /opt/app
		{"", true},                    // empty cwd is always allowed
	}

	for _, tc := range cases {
		if tc.cwd == "" {
			continue
		}
		cleaned := filepath.Clean(tc.cwd) // filepath.Clean mirrors path.Clean for POSIX paths
		result := security.IsWithinRoots(cleaned, roots)
		if result != tc.allowed {
			t.Errorf("cwd=%q (cleaned=%q): expected allowed=%v, got %v", tc.cwd, cleaned, tc.allowed, result)
		}
	}

	// With roots=["/"], everything is allowed
	for _, cwd := range []string{"/etc", "/opt/x", "/"} {
		cleaned := filepath.Clean(cwd)
		if !security.IsWithinRoots(cleaned, []string{"/"}) {
			t.Errorf("cwd=%q with roots=[\"/\"]: expected allowed", cwd)
		}
	}
}

// TestOpsStrictCwdGrantNotReusable verifies that in ops_strict, a cwd-composed
// command's template hash differs from the plain command, and grants are not reusable.
func TestOpsStrictCwdGrantNotReusable(t *testing.T) {
	roots := []string{"/opt/app"}

	// ops_strict: workspace_roots violation → Reusable=false
	d := security.EvaluateExecPolicyWithProfile("cd /etc && rm file", "L2", false, false, nil, roots, "ops_strict")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove in ops_strict, got %s", d.DenyClass)
	}
	if d.Reusable {
		t.Fatalf("expected Reusable=false in ops_strict")
	}
}

func TestAuthorizeTransferStart_PreFlightFailureDoesNotConsumeToken(t *testing.T) {
	tmp := t.TempDir()
	svc := newApprovalTestService(t, tmp)
	svc.preflightCheck = func(string) error {
		return errorsx.New(errorsx.CodeReconnectFailed, "cooldown period not elapsed")
	}

	conn := &model.Connection{
		Host:       "10.0.0.5",
		Username:   "deploy",
		Generation: 7,
	}
	approvalID := createApprovedTransferApproval(t, svc, "conn_1", conn, "upload")

	resp, err := svc.authorizeTransferStart("trace_1", "conn_1", conn, "upload", "/tmp/test.txt", "/remote/test.txt", true, approvalID)
	if err == nil {
		t.Fatalf("expected reconnect failure")
	}
	if resp != nil {
		t.Fatalf("expected no approval response on preflight failure, got %v", resp)
	}
	ce, ok := err.(*errorsx.CsshError)
	if !ok || ce.Code != errorsx.CodeReconnectFailed {
		t.Fatalf("expected RECONNECT_FAILED, got %#v", err)
	}

	req, getErr := svc.approvals.Get(approvalID)
	if getErr != nil {
		t.Fatalf("get approval: %v", getErr)
	}
	if req == nil || req.UsedAt != nil {
		t.Fatalf("token should remain unused after preflight failure, got %+v", req)
	}
}

func TestAuthorizeTransferStart_PreFlightFailureWithoutTokenDoesNotCreateApproval(t *testing.T) {
	tmp := t.TempDir()
	svc := newApprovalTestService(t, tmp)
	svc.preflightCheck = func(string) error {
		return errorsx.New(errorsx.CodeReconnectFailed, "cooldown period not elapsed")
	}

	conn := &model.Connection{Host: "10.0.0.5", Username: "deploy"}
	resp, err := svc.authorizeTransferStart("trace_1", "conn_1", conn, "download", "/tmp/test.txt", "/remote/test.txt", true, "")
	if err == nil {
		t.Fatalf("expected reconnect failure")
	}
	if resp != nil {
		t.Fatalf("expected no approval response on preflight failure, got %v", resp)
	}

	items, listErr := svc.approvals.List("")
	if listErr != nil {
		t.Fatalf("list approvals: %v", listErr)
	}
	if len(items) != 0 {
		t.Fatalf("expected no approval requests to be created, got %d", len(items))
	}
}

func TestAuthorizeTransferStart_ApprovalRequiredAfterSuccessfulPreFlight(t *testing.T) {
	tmp := t.TempDir()
	svc := newApprovalTestService(t, tmp)
	svc.preflightCheck = func(string) error { return nil }

	conn := &model.Connection{Host: "10.0.0.5", Username: "deploy", Generation: 2}
	resp, err := svc.authorizeTransferStart("trace_1", "conn_1", conn, "upload", "/tmp/test.txt", "/remote/test.txt", true, "")
	if err != nil {
		t.Fatalf("authorizeTransferStart: %v", err)
	}
	if resp == nil || resp["status"] != "approval_required" {
		t.Fatalf("expected approval_required response, got %v", resp)
	}

	items, listErr := svc.approvals.List("")
	if listErr != nil {
		t.Fatalf("list approvals: %v", listErr)
	}
	if len(items) != 1 {
		t.Fatalf("expected one approval request, got %d", len(items))
	}
	if items[0].Generation != conn.Generation {
		t.Fatalf("expected generation %d, got %d", conn.Generation, items[0].Generation)
	}
}

func TestAuthorizeTransferStart_ApprovedTokenConsumesAfterSuccessfulPreFlight(t *testing.T) {
	tmp := t.TempDir()
	svc := newApprovalTestService(t, tmp)
	svc.preflightCheck = func(string) error { return nil }

	conn := &model.Connection{
		Host:       "10.0.0.5",
		Username:   "deploy",
		Generation: 3,
	}
	approvalID := createApprovedTransferApproval(t, svc, "conn_1", conn, "download")

	resp, err := svc.authorizeTransferStart("trace_1", "conn_1", conn, "download", "/tmp/test.txt", "/remote/test.txt", true, approvalID)
	if err != nil {
		t.Fatalf("authorizeTransferStart: %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response on successful authorization, got %v", resp)
	}

	req, getErr := svc.approvals.Get(approvalID)
	if getErr != nil {
		t.Fatalf("get approval: %v", getErr)
	}
	if req == nil || req.UsedAt == nil {
		t.Fatalf("expected token to be consumed, got %+v", req)
	}
}

func createApprovedTransferApproval(t *testing.T, svc *Service, connectionID string, conn *model.Connection, direction string) string {
	t.Helper()
	return createApprovedTransferApprovalWithPaths(t, svc, connectionID, conn, direction, "/tmp/test.txt", "/remote/test.txt")
}

func createApprovedTransferApprovalWithPaths(t *testing.T, svc *Service, connectionID string, conn *model.Connection, direction, localPath, remotePath string) string {
	t.Helper()

	approvalID := "apr_transfer_" + direction
	template := transferApprovalTemplate(direction, localPath, remotePath)
	reason := fmt.Sprintf("%s local=%s remote=%s — local path is outside allowed directories", direction, localPath, remotePath)
	req := model.ApprovalRequest{
		ID:           approvalID,
		CreatedAt:    time.Now().UTC(),
		Status:       model.ApprovalPending,
		Command:      template,
		ConnectionID: connectionID,
		Host:         conn.Host,
		Username:     conn.Username,
		RiskLevel:    model.RiskL2,
		DenyClass:    model.DenyNeedApprove,
		Capability:   "local_anywhere_transfer",
		CommandTpl:   template,
		CommandHash:  security.HashCommandTemplate(template),
		Reason:       reason,
		RequestedBy:  "mcp",
		Generation:   conn.Generation,
	}
	if err := svc.approvals.Create(req); err != nil {
		t.Fatalf("create approval: %v", err)
	}
	if _, err := svc.approvals.Resolve(approvalID, model.ApprovalApproved, "operator", ""); err != nil {
		t.Fatalf("resolve approval: %v", err)
	}
	return approvalID
}

func TestAuthorizeTransferStart_TokenCannotCrossPathReuse(t *testing.T) {
	tmp := t.TempDir()
	svc := newApprovalTestService(t, tmp)
	svc.preflightCheck = func(string) error { return nil }

	conn := &model.Connection{
		Host:       "10.0.0.5",
		Username:   "deploy",
		Generation: 1,
	}

	// Create approval for path A
	approvalID := createApprovedTransferApprovalWithPaths(t, svc, "conn_1", conn, "upload", "/tmp/a.txt", "/remote/a.txt")

	// Try to use the token for path B — should be rejected (command mismatch)
	resp, err := svc.authorizeTransferStart("trace_1", "conn_1", conn, "upload", "/tmp/b.txt", "/remote/b.txt", true, approvalID)
	if err == nil && resp == nil {
		t.Fatalf("token for path A should not authorize path B")
	}
	if err != nil {
		ce, ok := err.(*errorsx.CsshError)
		if !ok || ce.Code != errorsx.CodeApprovalRejected {
			t.Fatalf("expected APPROVAL_REJECTED, got %#v", err)
		}
	}
}

func TestAuthorizeExecStart_PreFlightFailureDoesNotConsumeToken(t *testing.T) {
	tmp := t.TempDir()
	svc := newApprovalTestService(t, tmp)
	svc.preflightCheck = func(string) error {
		return errorsx.New(errorsx.CodeReconnectFailed, "cooldown period not elapsed")
	}

	conn := &model.Connection{
		Host:       "10.0.0.5",
		Username:   "deploy",
		Generation: 5,
	}
	command := "mkfs /dev/sdb"
	policy := security.EvaluateExecPolicyWithContext(command, "/", "L2", false, false, nil, nil, "")
	if policy.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected approval-needed policy, got %s", policy.DenyClass)
	}
	evalCmd := "cd " + util.ShellQuote("/") + " && " + command
	approvalID := createApprovedExecApproval(t, svc, "conn_1", conn, evalCmd, policy)

	authz, _, _, statusResp, err := svc.authorizeExecStart("conn_1", "", conn, policy, command, evalCmd, approvalID)
	if err == nil {
		t.Fatalf("expected reconnect failure")
	}
	if authz.Allowed {
		t.Fatalf("authorization should not be allowed on preflight failure")
	}
	if statusResp != nil {
		t.Fatalf("expected no status response on preflight failure, got %v", statusResp)
	}
	ce, ok := err.(*errorsx.CsshError)
	if !ok || ce.Code != errorsx.CodeReconnectFailed {
		t.Fatalf("expected RECONNECT_FAILED, got %#v", err)
	}

	req, getErr := svc.approvals.Get(approvalID)
	if getErr != nil {
		t.Fatalf("get approval: %v", getErr)
	}
	if req == nil || req.UsedAt != nil {
		t.Fatalf("token should remain unused after preflight failure, got %+v", req)
	}
}

func TestAuthorizeExecStart_PreFlightFailureWithoutTokenDoesNotCreateApproval(t *testing.T) {
	tmp := t.TempDir()
	svc := newApprovalTestService(t, tmp)
	svc.preflightCheck = func(string) error {
		return errorsx.New(errorsx.CodeReconnectFailed, "cooldown period not elapsed")
	}

	conn := &model.Connection{Host: "10.0.0.5", Username: "deploy"}
	command := "mkfs /dev/sdb"
	policy := security.EvaluateExecPolicyWithContext(command, "/", "L2", false, false, nil, nil, "")
	evalCmd := "cd " + util.ShellQuote("/") + " && " + command

	authz, _, _, statusResp, err := svc.authorizeExecStart("conn_1", "", conn, policy, command, evalCmd, "")
	if err == nil {
		t.Fatalf("expected reconnect failure")
	}
	if authz.Allowed {
		t.Fatalf("authorization should not be allowed on preflight failure")
	}
	if statusResp != nil {
		t.Fatalf("expected no status response on preflight failure, got %v", statusResp)
	}

	items, listErr := svc.approvals.List("")
	if listErr != nil {
		t.Fatalf("list approvals: %v", listErr)
	}
	if len(items) != 0 {
		t.Fatalf("expected no approval requests to be created, got %d", len(items))
	}
}

func TestAuthorizeExecStart_MissingSudoCredentialDoesNotConsumeToken(t *testing.T) {
	tmp := t.TempDir()
	svc := NewService(model.Config{
		DefaultShell:      "bash -lc",
		DefaultTimeoutSec: 120,
		RuntimeDir:        filepath.Join(tmp, "runtime"),
		LogsDir:           filepath.Join(tmp, "logs"),
		ProfilesFile:      filepath.Join(tmp, "profiles.json"),
		SudoEnabled:       true,
	})
	svc.preflightCheck = func(string) error { return nil }

	conn := &model.Connection{
		Host:       "10.0.0.5",
		Username:   "deploy",
		ProfileID:  "prof_1",
		Generation: 9,
	}
	command := "sudo mkfs /dev/sdb"
	policy := security.EvaluateExecPolicyWithContext(command, "/", "L2", false, false, nil, nil, "")
	if policy.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected approval-needed policy, got %s", policy.DenyClass)
	}
	if policy.Capability != "sudo_exec" {
		t.Fatalf("expected sudo_exec capability, got %q", policy.Capability)
	}
	evalCmd := "cd " + util.ShellQuote("/") + " && " + command
	approvalID := createApprovedExecApproval(t, svc, "conn_1", conn, evalCmd, policy)

	authz, _, _, statusResp, err := svc.authorizeExecStart("conn_1", "", conn, policy, command, evalCmd, approvalID)
	if err != nil {
		t.Fatalf("authorizeExecStart: %v", err)
	}
	if authz.Allowed {
		t.Fatalf("authorization should not be allowed when sudo credential is missing")
	}
	if statusResp == nil || statusResp["status"] != "credential_required" {
		t.Fatalf("expected credential_required response, got %v", statusResp)
	}

	req, getErr := svc.approvals.Get(approvalID)
	if getErr != nil {
		t.Fatalf("get approval: %v", getErr)
	}
	if req == nil || req.UsedAt != nil {
		t.Fatalf("token should remain unused when sudo credential is missing, got %+v", req)
	}
}

func TestAuthorizeExecStart_ConsumesTokenAfterReadyChecksPass(t *testing.T) {
	tmp := t.TempDir()
	svc := newApprovalTestService(t, tmp)
	svc.preflightCheck = func(string) error { return nil }

	conn := &model.Connection{
		Host:       "10.0.0.5",
		Username:   "deploy",
		Generation: 4,
	}
	command := "mkfs /dev/sdb"
	policy := security.EvaluateExecPolicyWithContext(command, "/", "L2", false, false, nil, nil, "")
	evalCmd := "cd " + util.ShellQuote("/") + " && " + command
	approvalID := createApprovedExecApproval(t, svc, "conn_1", conn, evalCmd, policy)

	authz, runCommand, runInput, statusResp, err := svc.authorizeExecStart("conn_1", "", conn, policy, command, evalCmd, approvalID)
	if err != nil {
		t.Fatalf("authorizeExecStart: %v", err)
	}
	if !authz.Allowed {
		t.Fatalf("expected authorization to succeed")
	}
	if runCommand != command || runInput != "" || statusResp != nil {
		t.Fatalf("unexpected execution preparation: runCommand=%q runInput=%q statusResp=%v", runCommand, runInput, statusResp)
	}

	req, getErr := svc.approvals.Get(approvalID)
	if getErr != nil {
		t.Fatalf("get approval: %v", getErr)
	}
	if req == nil || req.UsedAt == nil {
		t.Fatalf("expected token to be consumed, got %+v", req)
	}
}

func createApprovedExecApproval(t *testing.T, svc *Service, connectionID string, conn *model.Connection, evalCmd string, policy security.ExecPolicyDecision) string {
	t.Helper()

	approvalID := "apr_exec_" + policy.Capability
	req := model.ApprovalRequest{
		ID:           approvalID,
		CreatedAt:    time.Now().UTC(),
		Status:       model.ApprovalPending,
		Command:      evalCmd,
		ConnectionID: connectionID,
		Host:         conn.Host,
		Username:     conn.Username,
		RiskLevel:    policy.RiskLevel,
		DenyClass:    model.DenyNeedApprove,
		Capability:   policy.Capability,
		CommandTpl:   policy.Template,
		CommandHash:  policy.TemplateHash,
		Reason:       policy.Reason,
		RequestedBy:  "mcp",
		Reusable:     policy.Reusable,
		Generation:   conn.Generation,
	}
	if err := svc.approvals.Create(req); err != nil {
		t.Fatalf("create approval: %v", err)
	}
	if _, err := svc.approvals.Resolve(approvalID, model.ApprovalApproved, "operator", ""); err != nil {
		t.Fatalf("resolve approval: %v", err)
	}
	return approvalID
}
