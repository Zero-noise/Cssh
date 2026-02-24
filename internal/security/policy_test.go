package security

import (
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
	d := EvaluateExecPolicyWithProfile("rm -rf /", "L2", false, false, nil, nil)
	if d.DenyClass != model.DenyAlways {
		t.Fatalf("expected DenyAlways for rm -rf /, got: %s", d.DenyClass)
	}

	// DenyNone: ls
	d = EvaluateExecPolicyWithProfile("ls -la", "L2", false, false, nil, nil)
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for ls, got: %s", d.DenyClass)
	}

	// DenyNeedApprove: mkfs
	d = EvaluateExecPolicyWithProfile("mkfs /dev/sdb", "L2", false, false, nil, nil)
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for mkfs, got: %s", d.DenyClass)
	}

	// AllowDiskOps overrides mkfs to DenyNone
	d = EvaluateExecPolicyWithProfile("mkfs /dev/sdb", "L2", false, true, nil, nil)
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for mkfs with AllowDiskOps, got: %s", d.DenyClass)
	}
}

func TestEvaluateExecPolicyWorkspaceRoots(t *testing.T) {
	roots := []string{"/opt/app"}

	// rm within workspace roots → DenyNone
	d := EvaluateExecPolicyWithProfile("rm /opt/app/file", "L2", false, false, nil, roots)
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for rm within roots, got: %s", d.DenyClass)
	}

	// rm outside workspace roots → DenyNeedApprove
	d = EvaluateExecPolicyWithProfile("rm /etc/hosts", "L2", false, false, nil, roots)
	if d.DenyClass != model.DenyNeedApprove {
		t.Fatalf("expected DenyNeedApprove for rm outside roots, got: %s", d.DenyClass)
	}

	// cp within workspace roots → DenyNone
	d = EvaluateExecPolicyWithProfile("cp /opt/app/a /opt/app/b", "L2", false, false, nil, roots)
	if d.DenyClass != model.DenyNone {
		t.Fatalf("expected DenyNone for cp within roots, got: %s", d.DenyClass)
	}
}
