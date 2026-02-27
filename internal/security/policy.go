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
	DenyClass    model.DenyClass
	Capability   string
	Reason       string
	NeedsApprove bool
	Template     string
	TemplateHash string
	Reusable     bool // true = grant caching allowed (policy upgrade only, not dangerous-pattern match)
}

// EvaluateExecPolicy evaluates command risk using default policy (backward compat).
func EvaluateExecPolicy(command string) ExecPolicyDecision {
	return EvaluateExecPolicyWithProfile(command, "L2", false, false, nil, nil)
}

// EvaluateExecPolicyWithProfile evaluates command risk considering profile policy fields.
func EvaluateExecPolicyWithProfile(command string, maxAutoRisk string, allowReboot, allowDiskOps bool, denyPatterns, workspaceRoots []string) ExecPolicyDecision {
	cmd := strings.TrimSpace(command)
	dc := ClassifyDenyClass(cmd, maxAutoRisk, allowReboot, allowDiskOps, denyPatterns)
	risk := dc.RiskLevel
	reason := dc.Reason
	denyClass := dc.DenyClass

	capability := "exec_read"
	switch risk {
	case model.RiskL1:
		capability = "exec_write"
	case model.RiskL2:
		capability = "exec_high_risk"
	}

	if LooksLikeSudo(cmd) {
		capability = "sudo_exec"
		if risk == model.RiskL0 {
			risk = model.RiskL1
			reason = "sudo command with elevated privileges"
		} else if strings.TrimSpace(reason) == "" {
			reason = "sudo command with elevated privileges"
		}
	}

	// Track whether the DenyNeedApprove came from a policy upgrade (reusable grant).
	reusable := dc.IsUpgrade

	// For L1/L2 write commands with DenyClass==DenyNone: check workspace roots
	if denyClass == model.DenyNone && len(workspaceRoots) > 0 && (risk == model.RiskL1 || risk == model.RiskL2) {
		paths := extractAbsolutePaths(cmd)
		for _, p := range paths {
			if !IsWithinRoots(p, workspaceRoots) {
				denyClass = model.DenyNeedApprove
				reason = "command targets path outside workspace_roots: " + p
				reusable = true
				break
			}
		}
	}

	needsApprove := risk == model.RiskL2
	tpl := BuildCommandTemplate(cmd)
	return ExecPolicyDecision{
		RiskLevel:    risk,
		DenyClass:    denyClass,
		Capability:   capability,
		Reason:       reason,
		NeedsApprove: needsApprove,
		Template:     tpl,
		TemplateHash: HashCommandTemplate(tpl),
		Reusable:     reusable,
	}
}

// extractAbsolutePaths is best-effort: uses pathRE to find /absolute/paths in the command.
func extractAbsolutePaths(cmd string) []string {
	matches := pathRE.FindAllStringSubmatch(cmd, -1)
	var paths []string
	seen := map[string]bool{}
	for _, m := range matches {
		if len(m) >= 3 {
			p := strings.TrimSpace(m[2])
			if p != "" && !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}
	return paths
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
