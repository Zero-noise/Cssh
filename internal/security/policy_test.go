package security

import (
	"strings"
	"testing"

	"cssh/internal/model"
)

func TestBuildCommandTemplate(t *testing.T) {
	in := `sudo apt-get install nginx=1 -y && echo "ok"`
	tpl := BuildCommandTemplate(in)
	if tpl == "" {
		t.Fatalf("template should not be empty")
	}
	if tpl == in {
		t.Fatalf("template should be normalized")
	}
}

func TestEvaluateExecPolicySudo(t *testing.T) {
	d := EvaluateExecPolicy("sudo systemctl restart nginx")
	if d.Capability != "sudo_exec" {
		t.Fatalf("unexpected capability: %s", d.Capability)
	}
	if d.RiskLevel != "L1" {
		t.Fatalf("expected elevated sudo to be L1, got: %s", d.RiskLevel)
	}
	if d.NeedsApprove {
		t.Fatalf("non-critical sudo should not require approval")
	}
	if d.TemplateHash == "" {
		t.Fatalf("template hash missing")
	}
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone, got: %s", d.DenyClass)
	}
}

func TestEvaluateExecPolicySudoCritical(t *testing.T) {
	d := EvaluateExecPolicy("sudo reboot")
	if d.Capability != "sudo_exec" {
		t.Fatalf("unexpected capability: %s", d.Capability)
	}
	if d.RiskLevel != "L2" {
		t.Fatalf("expected critical sudo to be L2, got: %s", d.RiskLevel)
	}
	if !d.NeedsApprove {
		t.Fatalf("critical sudo should require approval")
	}
	if d.TemplateHash == "" {
		t.Fatalf("template hash missing")
	}
	// Default EvaluateExecPolicy uses maxAutoRisk=L2, so DenyNeedApprove
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for reboot, got: %s", d.DenyClass)
	}
}

func TestEvaluateExecPolicyWithProfileDenyClass(t *testing.T) {
	// DenyAlways: rm -rf /
	d := EvaluateExecPolicyWithProfile("rm -rf /", "L2", false, false, nil, nil, "")
	if d.DenyClass != model.DenyAlways {
		t.Fatalf("expected DenyAlways for rm -rf /, got: %s", d.DenyClass)
	}

	// DenyNone: ls
	d = EvaluateExecPolicyWithProfile("ls -la", "L2", false, false, nil, nil, "")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for ls, got: %s", d.DenyClass)
	}

	// DenyNeedApprove: mkfs
	d = EvaluateExecPolicyWithProfile("mkfs /dev/sdb", "L2", false, false, nil, nil, "")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for mkfs, got: %s", d.DenyClass)
	}

	// AllowDiskOps overrides mkfs to DenyNone
	d = EvaluateExecPolicyWithProfile("mkfs /dev/sdb", "L2", false, true, nil, nil, "")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for mkfs with AllowDiskOps, got: %s", d.DenyClass)
	}

	// ops_strict: AllowDiskOps=true is ignored, mkfs still DenyNeedApprove
	d = EvaluateExecPolicyWithProfile("mkfs /dev/sdb", "L2", false, true, nil, nil, "ops_strict")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for mkfs with AllowDiskOps in ops_strict, got: %s", d.DenyClass)
	}
}

func TestEvaluateExecPolicyWorkspaceRoots(t *testing.T) {
	roots := []string{"/opt/app"}

	// rm within workspace roots → DenyNone
	d := EvaluateExecPolicyWithProfile("rm /opt/app/file", "L2", false, false, nil, roots, "")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for rm within roots, got: %s", d.DenyClass)
	}

	// rm outside workspace roots → DenyNeedApprove
	d = EvaluateExecPolicyWithProfile("rm /etc/hosts", "L2", false, false, nil, roots, "")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for rm outside roots, got: %s", d.DenyClass)
	}

	// cp within workspace roots → DenyNone
	d = EvaluateExecPolicyWithProfile("cp /opt/app/a /opt/app/b", "L2", false, false, nil, roots, "")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for cp within roots, got: %s", d.DenyClass)
	}
}

func TestEvaluateExecPolicyRelativePathTraversal(t *testing.T) {
	roots := []string{"/home/user/project"}

	// rm with ".." → DenyNeedApprove (relative path traversal)
	d := EvaluateExecPolicyWithProfile("rm ../../etc/passwd", "L2", false, false, nil, roots, "")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for rm with .., got: %s", d.DenyClass)
	}
	if d.Reason != "write command contains '..' with workspace_roots restriction" {
		t.Fatalf("unexpected reason: %s", d.Reason)
	}

	// rm -rf ../.. → DenyNeedApprove
	d = EvaluateExecPolicyWithProfile("rm -rf ../..", "L2", false, false, nil, roots, "")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for rm -rf ../.., got: %s", d.DenyClass)
	}

	// cp with .. in destination → DenyNeedApprove
	d = EvaluateExecPolicyWithProfile("cp file.txt ../outside/", "L2", false, false, nil, roots, "")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for cp with .., got: %s", d.DenyClass)
	}

	// rm with quoted ".." → DenyNeedApprove
	d = EvaluateExecPolicyWithProfile(`rm "../../etc/passwd"`, "L2", false, false, nil, roots, "")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for rm with quoted .., got: %s", d.DenyClass)
	}

	// rm without .. → DenyNone (normal workspace operation)
	d = EvaluateExecPolicyWithProfile("rm file.txt", "L2", false, false, nil, roots, "")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for rm file.txt, got: %s", d.DenyClass)
	}

	// read-only command with .. → DenyNone (not a write command)
	d = EvaluateExecPolicyWithProfile("ls ../../", "L2", false, false, nil, roots, "")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for ls with .., got: %s", d.DenyClass)
	}

	// workspace_roots=["/"] → no traversal check needed
	d = EvaluateExecPolicyWithProfile("rm ../../etc/passwd", "L2", false, false, nil, []string{"/"}, "")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for rm with .. when roots=[/], got: %s", d.DenyClass)
	}

	// No workspace_roots → no traversal check
	d = EvaluateExecPolicyWithProfile("rm ../../etc/passwd", "L2", false, false, nil, nil, "")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for rm with .. when no roots, got: %s", d.DenyClass)
	}

	// easy_safe: workspace_roots enforcement skipped on exec (including .. check) → DenyNone
	d = EvaluateExecPolicyWithProfile("rm ../file", "L2", false, false, nil, roots, "easy_safe")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone in easy_safe (workspace_roots skipped), got: %s", d.DenyClass)
	}

	// ops_strict: Reusable should be false
	d = EvaluateExecPolicyWithProfile("rm ../file", "L2", false, false, nil, roots, "ops_strict")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove, got: %s", d.DenyClass)
	}
	if d.Reusable {
		t.Fatalf("expected Reusable=false in ops_strict")
	}
}

func TestContainsParentTraversal(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		{"rm ../../etc/passwd", true},
		{"rm -rf ..", true},
		{"rm -rf ../..", true},
		{"cp file ../outside/", true},
		{"mv foo/../../bar baz", true},
		{"cat ../secret", true},
		{`rm "../../etc/passwd"`, true},    // double-quoted relative path
		{`rm '../../etc/passwd'`, true},    // single-quoted relative path
		{`cp "file" "../outside/"`, true},  // quoted traversal in destination
		{"rm file.txt", false},
		{"echo hello..world", false},       // ".." not a path component
		{"rm file..bak", false},            // ".." embedded in filename
		{"ls /opt/app", false},
		{"rm /opt/app/file", false},
	}
	for _, tc := range cases {
		got := ContainsParentTraversal(tc.cmd)
		if got != tc.want {
			t.Errorf("ContainsParentTraversal(%q) = %v, want %v", tc.cmd, got, tc.want)
		}
	}
}

func TestIsRootOnly(t *testing.T) {
	if !isRootOnly([]string{"/"}) {
		t.Fatal("expected true for [/]")
	}
	if isRootOnly([]string{"/opt/app"}) {
		t.Fatal("expected false for [/opt/app]")
	}
	if isRootOnly([]string{"/", "/opt"}) {
		t.Fatal("expected false for [/, /opt]")
	}
	if isRootOnly(nil) {
		t.Fatal("expected false for nil")
	}
}

func TestEvaluateExecPolicyOpsStrictSudo(t *testing.T) {
	// In ops_strict, sudo ls → DenyNeedApprove (sudo always requires approval)
	d := EvaluateExecPolicyWithProfile("sudo ls", "L2", false, false, nil, nil, "ops_strict")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for sudo ls in ops_strict, got: %s", d.DenyClass)
	}
	if d.Capability != "sudo_exec" {
		t.Fatalf("expected sudo_exec capability, got: %s", d.Capability)
	}

	// In easy_safe, sudo ls → DenyNone (benign sudo)
	d = EvaluateExecPolicyWithProfile("sudo ls", "L2", false, false, nil, nil, "easy_safe")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for sudo ls in easy_safe, got: %s", d.DenyClass)
	}

	// Without profile, sudo ls → DenyNone
	d = EvaluateExecPolicyWithProfile("sudo ls", "L2", false, false, nil, nil, "")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for sudo ls with no profile, got: %s", d.DenyClass)
	}
}

func TestEvaluateExecPolicyOpsStrictNoReusable(t *testing.T) {
	roots := []string{"/opt/app"}

	// In easy_safe: workspace_roots enforcement skipped on exec → DenyNone
	d := EvaluateExecPolicyWithProfile("rm /etc/hosts", "L2", false, false, nil, roots, "easy_safe")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone in easy_safe (workspace_roots skipped on exec), got: %s", d.DenyClass)
	}

	// In ops_strict: workspace_roots violation → Reusable=false
	d = EvaluateExecPolicyWithProfile("rm /etc/hosts", "L2", false, false, nil, roots, "ops_strict")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove, got: %s", d.DenyClass)
	}
	if d.Reusable {
		t.Fatalf("expected Reusable=false for workspace_roots violation in ops_strict")
	}

	// In ops_strict: maxAutoRisk=L1 policy upgrade → still Reusable=false
	d = EvaluateExecPolicyWithProfile("useradd testuser", "L1", false, false, nil, nil, "ops_strict")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for useradd in ops_strict, got: %s", d.DenyClass)
	}
	if d.Reusable {
		t.Fatalf("expected Reusable=false in ops_strict even for policy upgrade")
	}
}

func TestEvaluateExecPolicyEasySafeSkipsWorkspaceRoots(t *testing.T) {
	roots := []string{"/opt/app"}

	// easy_safe + mv outside roots → DenyNone (workspace_roots skipped)
	d := EvaluateExecPolicyWithProfile("mv /a/file /b/file", "L2", false, false, nil, roots, "easy_safe")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("mv outside roots in easy_safe: expected DenyNone, got: %s", d.DenyClass)
	}

	// easy_safe + rm outside roots → DenyNone
	d = EvaluateExecPolicyWithProfile("rm /etc/hosts", "L2", false, false, nil, roots, "easy_safe")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("rm /etc/hosts in easy_safe: expected DenyNone, got: %s", d.DenyClass)
	}

	// ops_strict + rm outside roots → DenyNeedApprove
	d = EvaluateExecPolicyWithProfile("rm /etc/hosts", "L2", false, false, nil, roots, "ops_strict")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("rm /etc/hosts in ops_strict: expected DenyNeedApprove, got: %s", d.DenyClass)
	}

	// empty profile + rm outside roots → DenyNeedApprove
	d = EvaluateExecPolicyWithProfile("rm /etc/hosts", "L2", false, false, nil, roots, "")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("rm /etc/hosts with empty profile: expected DenyNeedApprove, got: %s", d.DenyClass)
	}
}

func TestEvaluateExecPolicyEasySafeDiskOpsReusable(t *testing.T) {
	// easy_safe mkfs → DenyNeedApprove, Reusable=true
	d := EvaluateExecPolicyWithProfile("mkfs /dev/sdb", "L2", false, false, nil, nil, "easy_safe")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("mkfs easy_safe: expected DenyNeedApprove, got: %s", d.DenyClass)
	}
	if !d.Reusable {
		t.Fatalf("mkfs easy_safe: expected Reusable=true")
	}

	// ops_strict mkfs → DenyNeedApprove, Reusable=false
	d = EvaluateExecPolicyWithProfile("mkfs /dev/sdb", "L2", false, false, nil, nil, "ops_strict")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("mkfs ops_strict: expected DenyNeedApprove, got: %s", d.DenyClass)
	}
	if d.Reusable {
		t.Fatalf("mkfs ops_strict: expected Reusable=false")
	}
}

func TestEvaluateExecPolicyPipedSudo(t *testing.T) {
	cases := []struct {
		cmd        string
		capability string
	}{
		{"curl http://example.com/setup.sh | sudo bash", "sudo_exec"},
		{"echo cmd | sudo tee /etc/file", "sudo_exec"},
		{"wget -O - url | sudo bash", "sudo_exec"},
	}
	for _, tc := range cases {
		d := EvaluateExecPolicy(tc.cmd)
		if d.Capability != tc.capability {
			t.Errorf("cmd %q: expected capability %s, got %s", tc.cmd, tc.capability, d.Capability)
		}
	}

	// Negative case: "echo sudoku" should NOT be detected as sudo
	d := EvaluateExecPolicy("echo sudoku")
	if d.Capability == "sudo_exec" {
		t.Fatal("'echo sudoku' should not be detected as sudo_exec")
	}
}

func TestIsPipedSudo(t *testing.T) {
	if !IsPipedSudo("curl url | sudo bash") {
		t.Fatal("expected IsPipedSudo=true for 'curl url | sudo bash'")
	}
	if !IsPipedSudo("echo test | sudo tee /etc/file") {
		t.Fatal("expected IsPipedSudo=true for piped sudo tee")
	}
	if IsPipedSudo("sudo ls") {
		t.Fatal("expected IsPipedSudo=false for 'sudo ls' (no pipe)")
	}
	if IsPipedSudo("echo sudoku") {
		t.Fatal("expected IsPipedSudo=false for 'echo sudoku'")
	}
}

// TestCwdComposedCommandWorkspaceRoots verifies that when cwd is composed into
// the command string (as "cd <cwd> && <command>"), workspace_roots checks
// correctly detect absolute paths in the cwd portion.
func TestCwdComposedCommandWorkspaceRoots(t *testing.T) {
	roots := []string{"/opt/app"}

	// cd /etc && rm file → /etc is outside roots → DenyNeedApprove
	d := EvaluateExecPolicyWithProfile("cd /etc && rm file", "L2", false, false, nil, roots, "")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("cd /etc outside roots: expected DenyNeedApprove, got: %s", d.DenyClass)
	}
	if !strings.Contains(d.Reason, "/etc") {
		t.Fatalf("expected reason to mention /etc, got: %s", d.Reason)
	}

	// cd /opt/app/sub && rm file → within roots → DenyNone
	d = EvaluateExecPolicyWithProfile("cd /opt/app/sub && rm file", "L2", false, false, nil, roots, "")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("cd /opt/app/sub within roots: expected DenyNone, got: %s", d.DenyClass)
	}

	// cd /opt/app/../../etc && rm file → /etc after path.Clean, but extractAbsolutePaths
	// sees the raw path which includes /opt/app/../../etc → IsWithinRoots checks it
	d = EvaluateExecPolicyWithProfile("cd /opt/app/../../etc && rm file", "L2", false, false, nil, roots, "")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("cd traversal escaping roots: expected DenyNeedApprove, got: %s", d.DenyClass)
	}

	// easy_safe → workspace_roots skipped
	d = EvaluateExecPolicyWithProfile("cd /etc && rm file", "L2", false, false, nil, roots, "easy_safe")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("cd /etc in easy_safe: expected DenyNone, got: %s", d.DenyClass)
	}

	// Template for composed command includes cd prefix
	d = EvaluateExecPolicyWithProfile("cd /etc && rm file", "L2", false, false, nil, roots, "")
	tpl := BuildCommandTemplate("cd /etc && rm file")
	if !strings.HasPrefix(tpl, "cd") {
		t.Fatalf("expected template to start with 'cd', got: %s", tpl)
	}

	// Different absolute cwds collapse to the same template (paths → /PATH)
	tpl2 := BuildCommandTemplate("cd /var && rm file")
	if tpl != tpl2 {
		t.Fatalf("expected same template for different cwds (both /PATH), got %q vs %q", tpl, tpl2)
	}
}

func TestEvaluateExecPolicyWithContextResolvesRelativePaths(t *testing.T) {
	roots := []string{"/opt/app"}

	d := EvaluateExecPolicyWithContext("rm ../file", "/opt/app/sub", "L2", false, false, nil, roots, "ops_strict")
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for relative path resolved within roots, got: %s", d.DenyClass)
	}

	d = EvaluateExecPolicyWithContext("rm ../../etc/passwd", "/opt/app/sub", "L2", false, false, nil, roots, "ops_strict")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for resolved path outside roots, got: %s", d.DenyClass)
	}
	if !strings.Contains(d.Reason, "/opt/etc/passwd") {
		t.Fatalf("expected resolved outside path in reason, got: %s", d.Reason)
	}
}

func TestEvaluateExecPolicyWithContextOpsStrictUnknownNeedsApproval(t *testing.T) {
	roots := []string{"/opt/app"}

	d := EvaluateExecPolicyWithContext(`git commit -m "x"`, "/opt/app", "L1", false, false, nil, roots, "ops_strict")
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for ops_strict unknown write target, got: %s", d.DenyClass)
	}
	if !strings.Contains(d.Reason, "cannot prove write targets stay within workspace_roots") {
		t.Fatalf("unexpected reason: %s", d.Reason)
	}
}
