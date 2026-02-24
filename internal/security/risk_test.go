package security

import (
	"testing"

	"cssh/internal/model"
)

func TestClassifyCommandRisk(t *testing.T) {
	cases := []struct {
		cmd  string
		want model.RiskLevel
	}{
		{"ls -la", model.RiskL0},
		{"echo hi > file.txt", model.RiskL1},
		{"rm -rf /", model.RiskL2},
		{"sudo rm -rf /", model.RiskL2},
		{"sudo /bin/rm -fr -- /", model.RiskL2},
		{"rm -rf /*", model.RiskL2},
		{"sudo reboot", model.RiskL2},
		{"init 0", model.RiskL2},
		{"find / -delete", model.RiskL2},
		{"sudo find / -delete", model.RiskL2},
		{"find /etc -delete", model.RiskL2},
		{"find / -name '*.tmp' -delete", model.RiskL2},
		{"find -L /etc -delete", model.RiskL2},
		{"find /tmp -delete", model.RiskL1},
		{"find -L /tmp -delete", model.RiskL1},
		{"find . -delete", model.RiskL1},
		{":(){ :|:& };:", model.RiskL2},
		{"rm -rf /tmp/work", model.RiskL1},
	}
	for _, tc := range cases {
		got, _ := ClassifyCommandRisk(tc.cmd)
		if got != tc.want {
			t.Fatalf("cmd %q: got %s want %s", tc.cmd, got, tc.want)
		}
	}
}

func TestClassifyDenyClass(t *testing.T) {
	cases := []struct {
		cmd       string
		wantDC    model.DenyClass
		wantRisk  model.RiskLevel
	}{
		// DenyAlways: fork bomb
		{":(){ :|:& };:", model.DenyAlways, model.RiskL2},
		// DenyAlways: rm -rf /
		{"rm -rf /", model.DenyAlways, model.RiskL2},
		{"sudo rm -rf /", model.DenyAlways, model.RiskL2},
		// DenyAlways: find -delete on critical paths
		{"find / -delete", model.DenyAlways, model.RiskL2},
		{"find /etc -delete", model.DenyAlways, model.RiskL2},
		// DenyNeedApprove: dangerous disk ops
		{"mkfs /dev/sdb", model.DenyNeedApprove, model.RiskL2},
		{"dd of=/dev/sda bs=512 count=1", model.DenyNeedApprove, model.RiskL2},
		{"wipefs -a /dev/sdb", model.DenyNeedApprove, model.RiskL2},
		{"fdisk /dev/sdb", model.DenyNeedApprove, model.RiskL2},
		{"sfdisk /dev/sdb", model.DenyNeedApprove, model.RiskL2},
		{"parted /dev/sdb", model.DenyNeedApprove, model.RiskL2},
		// DenyNeedApprove: shutdown/reboot
		{"shutdown -h now", model.DenyNeedApprove, model.RiskL2},
		{"reboot", model.DenyNeedApprove, model.RiskL2},
		{"poweroff", model.DenyNeedApprove, model.RiskL2},
		{"halt", model.DenyNeedApprove, model.RiskL2},
		{"init 0", model.DenyNeedApprove, model.RiskL2},
		{"init 6", model.DenyNeedApprove, model.RiskL2},
		// DenyNone (L2 audit): useradd, systemctl stop, etc.
		{"useradd testuser", model.DenyNone, model.RiskL2},
		{"usermod -aG docker testuser", model.DenyNone, model.RiskL2},
		{"userdel testuser", model.DenyNone, model.RiskL2},
		{"systemctl stop nginx", model.DenyNone, model.RiskL2},
		{"systemctl disable sshd", model.DenyNone, model.RiskL2},
		{"chmod 777 /tmp/file", model.DenyNone, model.RiskL2},
		{"chown -R root /opt", model.DenyNone, model.RiskL2},
		{"dd if=/dev/zero of=/tmp/test bs=1M count=100", model.DenyNone, model.RiskL2},
		// DenyNone (L1): write ops
		{"echo hi > file.txt", model.DenyNone, model.RiskL1},
		{"rm -rf /tmp/work", model.DenyNone, model.RiskL1},
		{"find /tmp -delete", model.DenyNone, model.RiskL1},
		// DenyNone (L0): read-only
		{"ls -la", model.DenyNone, model.RiskL0},
		{"cat /etc/hosts", model.DenyNone, model.RiskL0},
	}
	for _, tc := range cases {
		dc := ClassifyDenyClass(tc.cmd, "L2", false, false, nil)
		if dc.DenyClass != tc.wantDC {
			t.Errorf("cmd %q: DenyClass got %s want %s", tc.cmd, dc.DenyClass, tc.wantDC)
		}
		if dc.RiskLevel != tc.wantRisk {
			t.Errorf("cmd %q: RiskLevel got %s want %s", tc.cmd, dc.RiskLevel, tc.wantRisk)
		}
	}
}

func TestClassifyDenyClassWrapperBypass(t *testing.T) {
	cases := []struct {
		cmd    string
		wantDC model.DenyClass
	}{
		{`bash -c 'rm -rf /'`, model.DenyAlways},
		{`sh -c "rm -rf /"`, model.DenyAlways},
		{`eval "reboot"`, model.DenyNeedApprove},
		{`echo "mkfs /dev/sdb" | bash`, model.DenyNeedApprove},
		{`bash -c 'ls -la'`, model.DenyNone},
	}
	for _, tc := range cases {
		dc := ClassifyDenyClass(tc.cmd, "L2", false, false, nil)
		if dc.DenyClass != tc.wantDC {
			t.Errorf("cmd %q: DenyClass got %s want %s", tc.cmd, dc.DenyClass, tc.wantDC)
		}
	}
}

func TestClassifyDenyClassProfileOverrides(t *testing.T) {
	// shutdown with AllowReboot=true → DenyNone
	dc := ClassifyDenyClass("shutdown -h now", "L2", true, false, nil)
	if dc.DenyClass != model.DenyNone {
		t.Errorf("shutdown with AllowReboot=true: got %s want %s", dc.DenyClass, model.DenyNone)
	}
	dc = ClassifyDenyClass("reboot", "L2", true, false, nil)
	if dc.DenyClass != model.DenyNone {
		t.Errorf("reboot with AllowReboot=true: got %s want %s", dc.DenyClass, model.DenyNone)
	}

	// mkfs with AllowDiskOps=true → DenyNone
	dc = ClassifyDenyClass("mkfs /dev/sdb", "L2", false, true, nil)
	if dc.DenyClass != model.DenyNone {
		t.Errorf("mkfs with AllowDiskOps=true: got %s want %s", dc.DenyClass, model.DenyNone)
	}
	dc = ClassifyDenyClass("dd of=/dev/sda bs=512", "L2", false, true, nil)
	if dc.DenyClass != model.DenyNone {
		t.Errorf("dd of=/dev with AllowDiskOps=true: got %s want %s", dc.DenyClass, model.DenyNone)
	}

	// maxAutoRisk=L1 upgrades L2 DenyNone to DenyNeedApprove
	dc = ClassifyDenyClass("useradd testuser", "L1", false, false, nil)
	if dc.DenyClass != model.DenyNeedApprove {
		t.Errorf("useradd with maxAutoRisk=L1: got %s want %s", dc.DenyClass, model.DenyNeedApprove)
	}

	// user deny patterns
	dc = ClassifyDenyClass("apt-get remove nginx", "L2", false, false, []string{`apt-get\s+remove`})
	if dc.DenyClass != model.DenyNeedApprove {
		t.Errorf("user deny pattern: got %s want %s", dc.DenyClass, model.DenyNeedApprove)
	}
}

func TestUnwrapShellWrappers(t *testing.T) {
	cases := []struct {
		cmd  string
		want int // minimum number of variants
	}{
		{`bash -c 'rm -rf /'`, 2},
		{`sh -c "ls -la"`, 2},
		{`eval "reboot"`, 2},
		{`echo "mkfs /dev/sdb" | bash`, 2},
		{`ls -la`, 1},
	}
	for _, tc := range cases {
		variants := UnwrapShellWrappers(tc.cmd)
		if len(variants) < tc.want {
			t.Errorf("cmd %q: got %d variants, want >= %d: %v", tc.cmd, len(variants), tc.want, variants)
		}
	}
}
