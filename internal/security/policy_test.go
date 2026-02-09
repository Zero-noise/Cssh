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
	d := EvaluateExecPolicy("sudo systemctl restart nginx", true)
	if d.Capability != "sudo_exec" {
		t.Fatalf("unexpected capability: %s", d.Capability)
	}
	if !d.NeedsApprove {
		t.Fatalf("sudo should require approval")
	}
	if d.TemplateHash == "" {
		t.Fatalf("template hash missing")
	}
}
