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
	Reusable     bool // true = grant caching allowed (policy-driven: maxAutoRisk upgrade, easy_safe profile, or workspace_roots violation)
}

// EvaluateExecPolicy evaluates command risk using default policy (backward compat).
func EvaluateExecPolicy(command string) ExecPolicyDecision {
	return EvaluateExecPolicyWithProfile(command, "L2", false, false, nil, nil, "")
}

// EvaluateExecPolicyWithProfile evaluates command risk considering profile policy fields.
func EvaluateExecPolicyWithProfile(command string, maxAutoRisk string, allowReboot, allowDiskOps bool, denyPatterns, workspaceRoots []string, securityProfile string) ExecPolicyDecision {
	cmd := strings.TrimSpace(command)
	dc := ClassifyDenyClass(cmd, maxAutoRisk, allowReboot, allowDiskOps, denyPatterns, securityProfile)
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

	// ops_strict: all sudo commands require approval regardless of underlying risk
	if LooksLikeSudo(cmd) && strings.EqualFold(securityProfile, "ops_strict") && denyClass == model.DenyNone {
		denyClass = model.DenyNeedApprove
		reason = "sudo requires approval in ops_strict mode"
	}

	// Track whether the DenyNeedApprove came from a policy upgrade (reusable grant).
	reusable := dc.IsUpgrade

	// For L1/L2 write commands with DenyClass==DenyNone: check workspace roots
	// easy_safe skips workspace_roots enforcement on exec (file tools still enforce via resolveAndCheckPath)
	if denyClass == model.DenyNone && len(workspaceRoots) > 0 && (risk == model.RiskL1 || risk == model.RiskL2) &&
		!strings.EqualFold(securityProfile, "easy_safe") {
		paths := extractAbsolutePaths(cmd)
		for _, p := range paths {
			if !IsWithinRoots(p, workspaceRoots) {
				denyClass = model.DenyNeedApprove
				reason = "command targets path outside workspace_roots: " + p
				reusable = true
				break
			}
		}
		// Relative path traversal: ".." can escape workspace_roots without any absolute path.
		// When workspace_roots is configured and not just ["/"], flag write commands containing "..".
		if denyClass == model.DenyNone && !isRootOnly(workspaceRoots) && containsParentTraversal(cmd) {
			denyClass = model.DenyNeedApprove
			reason = "write command contains '..' with workspace_roots restriction"
			reusable = true
		}
	}

	// ops_strict: no reusable grants — every approval is one-shot
	if strings.EqualFold(securityProfile, "ops_strict") {
		reusable = false
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
// NOTE: This only detects absolute paths. Relative path traversal (e.g. "../../etc")
// is handled separately by containsParentTraversal in the workspace_roots check.
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

var pipedSudoRE = regexp.MustCompile(`\|\s*sudo(\s|$)`)

func LooksLikeSudo(command string) bool {
	cmd := strings.TrimSpace(command)
	if strings.HasPrefix(cmd, "sudo ") || cmd == "sudo" {
		return true
	}
	return pipedSudoRE.MatchString(cmd)
}

// IsPipedSudo returns true when sudo appears after a pipe (e.g. "curl | sudo bash").
func IsPipedSudo(command string) bool {
	return pipedSudoRE.MatchString(strings.TrimSpace(command))
}

// parentTraversalRE matches ".." as a path component (boundary-aware).
// Covers: .., ../, ../../, foo/../bar, "../escape", '../escape', etc.
var parentTraversalRE = regexp.MustCompile(`(^|[\s/"'])\.\.([/\s;|&"']|$)`)

// containsParentTraversal returns true if the command string contains ".." as a path component.
func containsParentTraversal(cmd string) bool {
	return parentTraversalRE.MatchString(cmd)
}

// isRootOnly returns true if workspace_roots is effectively ["/"].
func isRootOnly(roots []string) bool {
	if len(roots) != 1 {
		return false
	}
	return strings.TrimSpace(roots[0]) == "/"
}
