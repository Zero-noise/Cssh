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
		// New L1 write patterns: package managers, kill, systemctl start/restart
		{"apt-get install nginx", model.DenyNone, model.RiskL1},
		{"yum remove httpd", model.DenyNone, model.RiskL1},
		{"pip install flask", model.DenyNone, model.RiskL1},
		{"npm install express", model.DenyNone, model.RiskL1},
		{"brew install wget", model.DenyNone, model.RiskL1},
		{"kill 1234", model.DenyNone, model.RiskL1},
		{"systemctl restart nginx", model.DenyNone, model.RiskL1},
		// New L2 high-risk patterns: pkill/killall, crontab, firewall, docker
		{"pkill nginx", model.DenyNone, model.RiskL2},
		{"killall node", model.DenyNone, model.RiskL2},
		{"crontab -r", model.DenyNone, model.RiskL2},
		{"iptables -F", model.DenyNone, model.RiskL2},
		{"iptables -A INPUT -j DROP", model.DenyNone, model.RiskL2},
		{"ufw allow 22", model.DenyNone, model.RiskL2},
		{"docker rm web", model.DenyNone, model.RiskL2},
		// Verify read-only variants stay L0 (counterparts to L2 write patterns above)
		{"iptables -L", model.DenyNone, model.RiskL0},
		{"iptables -S", model.DenyNone, model.RiskL0},
		{"ip6tables -L", model.DenyNone, model.RiskL0},
		{"firewall-cmd --list-all", model.DenyNone, model.RiskL0},
		{"firewall-cmd --query-port=22/tcp", model.DenyNone, model.RiskL0},
		{"crontab -l", model.DenyNone, model.RiskL0},
		{"ufw status", model.DenyNone, model.RiskL0},
		{"docker ps", model.DenyNone, model.RiskL0},
		// Verify alternate variants (ip6tables, podman, firewall-cmd write)
		{"ip6tables -F", model.DenyNone, model.RiskL2},
		{"ip6tables -A INPUT -j DROP", model.DenyNone, model.RiskL2},
		{"podman rm web", model.DenyNone, model.RiskL2},
		{"podman stop web", model.DenyNone, model.RiskL2},
		{"podman kill web", model.DenyNone, model.RiskL2},
		{"firewall-cmd --reload", model.DenyNone, model.RiskL2},
		{"firewall-cmd --add-port=22/tcp", model.DenyNone, model.RiskL2},
		// DenyNone (L0): read-only
		{"ls -la", model.DenyNone, model.RiskL0},
		{"cat /etc/hosts", model.DenyNone, model.RiskL0},
	}
	for _, tc := range cases {
		dc := ClassifyDenyClass(tc.cmd, "L2", false, false, nil, "")
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
		dc := ClassifyDenyClass(tc.cmd, "L2", false, false, nil, "")
		if dc.DenyClass != tc.wantDC {
			t.Errorf("cmd %q: DenyClass got %s want %s", tc.cmd, dc.DenyClass, tc.wantDC)
		}
	}
}

func TestClassifyDenyClassProfileOverrides(t *testing.T) {
	// shutdown with AllowReboot=true → DenyNone
	dc := ClassifyDenyClass("shutdown -h now", "L2", true, false, nil, "")
	if dc.DenyClass != model.DenyNone {
		t.Errorf("shutdown with AllowReboot=true: got %s want %s", dc.DenyClass, model.DenyNone)
	}
	dc = ClassifyDenyClass("reboot", "L2", true, false, nil, "")
	if dc.DenyClass != model.DenyNone {
		t.Errorf("reboot with AllowReboot=true: got %s want %s", dc.DenyClass, model.DenyNone)
	}

	// mkfs with AllowDiskOps=true → DenyNone
	dc = ClassifyDenyClass("mkfs /dev/sdb", "L2", false, true, nil, "")
	if dc.DenyClass != model.DenyNone {
		t.Errorf("mkfs with AllowDiskOps=true: got %s want %s", dc.DenyClass, model.DenyNone)
	}
	dc = ClassifyDenyClass("dd of=/dev/sda bs=512", "L2", false, true, nil, "")
	if dc.DenyClass != model.DenyNone {
		t.Errorf("dd of=/dev with AllowDiskOps=true: got %s want %s", dc.DenyClass, model.DenyNone)
	}

	// maxAutoRisk=L1 upgrades L2 DenyNone to DenyNeedApprove
	dc = ClassifyDenyClass("useradd testuser", "L1", false, false, nil, "")
	if dc.DenyClass != model.DenyNeedApprove {
		t.Errorf("useradd with maxAutoRisk=L1: got %s want %s", dc.DenyClass, model.DenyNeedApprove)
	}

	// user deny patterns
	dc = ClassifyDenyClass("apt-get remove nginx", "L2", false, false, []string{`apt-get\s+remove`}, "")
	if dc.DenyClass != model.DenyNeedApprove {
		t.Errorf("user deny pattern: got %s want %s", dc.DenyClass, model.DenyNeedApprove)
	}

	// ops_strict: AllowReboot=true still results in DenyNeedApprove
	dc = ClassifyDenyClass("shutdown -h now", "L2", true, false, nil, "ops_strict")
	if dc.DenyClass != model.DenyNeedApprove {
		t.Errorf("shutdown with AllowReboot=true in ops_strict: got %s want %s", dc.DenyClass, model.DenyNeedApprove)
	}
	dc = ClassifyDenyClass("reboot", "L2", true, false, nil, "ops_strict")
	if dc.DenyClass != model.DenyNeedApprove {
		t.Errorf("reboot with AllowReboot=true in ops_strict: got %s want %s", dc.DenyClass, model.DenyNeedApprove)
	}

	// ops_strict: AllowDiskOps=true still results in DenyNeedApprove
	dc = ClassifyDenyClass("mkfs /dev/sdb", "L2", false, true, nil, "ops_strict")
	if dc.DenyClass != model.DenyNeedApprove {
		t.Errorf("mkfs with AllowDiskOps=true in ops_strict: got %s want %s", dc.DenyClass, model.DenyNeedApprove)
	}
	dc = ClassifyDenyClass("dd of=/dev/sda bs=512", "L2", false, true, nil, "ops_strict")
	if dc.DenyClass != model.DenyNeedApprove {
		t.Errorf("dd of=/dev with AllowDiskOps=true in ops_strict: got %s want %s", dc.DenyClass, model.DenyNeedApprove)
	}
}

func TestClassifyDenyClassEasySafe(t *testing.T) {
	// mkfs with easy_safe → DenyNeedApprove, IsUpgrade=true (reusable)
	dc := ClassifyDenyClass("mkfs /dev/sdb", "L2", false, false, nil, "easy_safe")
	if dc.DenyClass != model.DenyNeedApprove {
		t.Errorf("mkfs easy_safe: DenyClass got %s want %s", dc.DenyClass, model.DenyNeedApprove)
	}
	if !dc.IsUpgrade {
		t.Errorf("mkfs easy_safe: expected IsUpgrade=true (reusable)")
	}

	// mkfs with easy_safe + AllowDiskOps=true → DenyNone (explicit config honored)
	dc = ClassifyDenyClass("mkfs /dev/sdb", "L2", false, true, nil, "easy_safe")
	if dc.DenyClass != model.DenyNone {
		t.Errorf("mkfs easy_safe+AllowDiskOps: DenyClass got %s want %s", dc.DenyClass, model.DenyNone)
	}

	// shutdown with easy_safe → DenyNeedApprove (unchanged behavior)
	dc = ClassifyDenyClass("shutdown -h now", "L2", false, false, nil, "easy_safe")
	if dc.DenyClass != model.DenyNeedApprove {
		t.Errorf("shutdown easy_safe: DenyClass got %s want %s", dc.DenyClass, model.DenyNeedApprove)
	}

	// shutdown with easy_safe + AllowReboot=true → DenyNone (explicit config honored)
	dc = ClassifyDenyClass("shutdown -h now", "L2", true, false, nil, "easy_safe")
	if dc.DenyClass != model.DenyNone {
		t.Errorf("shutdown easy_safe+AllowReboot: DenyClass got %s want %s", dc.DenyClass, model.DenyNone)
	}

	// rm -rf / with easy_safe → DenyAlways (catastrophic still blocked)
	dc = ClassifyDenyClass("rm -rf /", "L2", false, false, nil, "easy_safe")
	if dc.DenyClass != model.DenyAlways {
		t.Errorf("rm -rf / easy_safe: DenyClass got %s want %s", dc.DenyClass, model.DenyAlways)
	}

	// useradd with easy_safe → DenyNone, L2
	dc = ClassifyDenyClass("useradd testuser", "L2", false, false, nil, "easy_safe")
	if dc.DenyClass != model.DenyNone {
		t.Errorf("useradd easy_safe: DenyClass got %s want %s", dc.DenyClass, model.DenyNone)
	}
	if dc.RiskLevel != model.RiskL2 {
		t.Errorf("useradd easy_safe: RiskLevel got %s want %s", dc.RiskLevel, model.RiskL2)
	}
}

func TestClassifyDenyClassOpsStrictNewPatterns(t *testing.T) {
	// New L2 patterns with maxAutoRisk=L1 → DenyNeedApprove
	cases := []struct {
		cmd    string
		wantDC model.DenyClass
	}{
		{"iptables -F", model.DenyNeedApprove},
		{"pkill nginx", model.DenyNeedApprove},
		{"crontab -r", model.DenyNeedApprove},
		{"docker rm web", model.DenyNeedApprove},
	}
	for _, tc := range cases {
		dc := ClassifyDenyClass(tc.cmd, "L1", false, false, nil, "ops_strict")
		if dc.DenyClass != tc.wantDC {
			t.Errorf("cmd %q with maxAutoRisk=L1: DenyClass got %s want %s", tc.cmd, dc.DenyClass, tc.wantDC)
		}
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
