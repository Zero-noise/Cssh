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
	}
	for _, tc := range cases {
		got, _ := ClassifyCommandRisk(tc.cmd)
		if got != tc.want {
			t.Fatalf("cmd %q: got %s want %s", tc.cmd, got, tc.want)
		}
	}
}
