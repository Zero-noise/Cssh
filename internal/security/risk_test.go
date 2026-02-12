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
