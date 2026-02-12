package security

import "testing"

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
}
