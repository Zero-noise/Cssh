package security

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"cssh/internal/model"
)

var (
	spaceRE   = regexp.MustCompile(`\s+`)
	numberRE  = regexp.MustCompile(`\b\d+\b`)
	singleQRE = regexp.MustCompile(`'[^']*'`)
	doubleQRE = regexp.MustCompile(`"[^"]*"`)
	pathRE    = regexp.MustCompile(`(^|\s)(/[^ \t;|&]+)`)
)

type ExecPolicyDecision struct {
	RiskLevel    model.RiskLevel
	Capability   string
	Reason       string
	NeedsApprove bool
	Template     string
	TemplateHash string
}

func EvaluateExecPolicy(command string) ExecPolicyDecision {
	cmd := strings.TrimSpace(command)
	risk, reason := ClassifyCommandRisk(cmd)
	capability := "exec_read"
	switch risk {
	case model.RiskL1:
		capability = "exec_write"
	case model.RiskL2:
		capability = "exec_high_risk"
	}

	if LooksLikeSudo(cmd) {
		capability = "sudo_exec"
		// Sudo elevates privilege but is not always "critical destructive".
		// Keep explicit approval for critical commands (risk L2), not all sudo.
		if risk == model.RiskL0 {
			risk = model.RiskL1
			reason = "sudo command with elevated privileges"
		} else if strings.TrimSpace(reason) == "" {
			reason = "sudo command with elevated privileges"
		}
	}

	needsApprove := risk == model.RiskL2
	tpl := BuildCommandTemplate(cmd)
	return ExecPolicyDecision{
		RiskLevel:    risk,
		Capability:   capability,
		Reason:       reason,
		NeedsApprove: needsApprove,
		Template:     tpl,
		TemplateHash: HashCommandTemplate(tpl),
	}
}

func BuildCommandTemplate(command string) string {
	out := strings.TrimSpace(strings.ToLower(command))
	out = singleQRE.ReplaceAllString(out, "'*'")
	out = doubleQRE.ReplaceAllString(out, "\"*\"")
	out = pathRE.ReplaceAllString(out, "${1}/PATH")
	out = numberRE.ReplaceAllString(out, "N")
	out = spaceRE.ReplaceAllString(out, " ")
	return strings.TrimSpace(out)
}

func HashCommandTemplate(template string) string {
	sum := sha256.Sum256([]byte(template))
	return hex.EncodeToString(sum[:])
}

func LooksLikeSudo(command string) bool {
	cmd := strings.TrimSpace(command)
	return strings.HasPrefix(cmd, "sudo ") || cmd == "sudo"
}
