package security

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
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

// EvaluateExecPolicyWithContext evaluates command risk using an explicit
// working-directory security context. The cwd is included in grant identity so
// approvals do not bleed across different directories.
func EvaluateExecPolicyWithContext(command, cwd, maxAutoRisk string, allowReboot, allowDiskOps bool, denyPatterns, workspaceRoots []string, securityProfile string) ExecPolicyDecision {
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

	normalizedCWD := normalizePolicyCWD(cwd)

	// For L1/L2 write commands with DenyClass==DenyNone: check workspace roots.
	// easy_safe skips workspace_roots enforcement on exec (file tools still enforce via resolveAndCheckPath).
	if denyClass == model.DenyNone &&
		len(workspaceRoots) > 0 &&
		(risk == model.RiskL1 || risk == model.RiskL2) &&
		!strings.EqualFold(securityProfile, "easy_safe") {
		check := evaluateWorkspaceAccess(cmd, normalizedCWD, workspaceRoots)
		switch check.status {
		case workspaceProofOutside:
			denyClass = model.DenyNeedApprove
			reason = check.reason
			reusable = true
		case workspaceProofUnknown:
			if strings.EqualFold(securityProfile, "ops_strict") {
				denyClass = model.DenyNeedApprove
				reason = check.reason
				reusable = false
			}
		}
	}

	// ops_strict: no reusable grants — every approval is one-shot
	if strings.EqualFold(securityProfile, "ops_strict") {
		reusable = false
	}

	needsApprove := risk == model.RiskL2
	tpl := BuildCommandContextTemplate(normalizedCWD, cmd)
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

// EvaluateExecPolicyWithProfile evaluates command risk considering profile policy fields.
func EvaluateExecPolicyWithProfile(command string, maxAutoRisk string, allowReboot, allowDiskOps bool, denyPatterns, workspaceRoots []string, securityProfile string) ExecPolicyDecision {
	return EvaluateExecPolicyWithContext(command, "", maxAutoRisk, allowReboot, allowDiskOps, denyPatterns, workspaceRoots, securityProfile)
}

// extractAbsolutePaths is best-effort: uses pathRE to find /absolute/paths in the command.
// NOTE: This only detects absolute paths. Relative path traversal (e.g. "../../etc")
// is handled separately by ContainsParentTraversal in the workspace_roots check.
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

func BuildCommandContextTemplate(cwd, command string) string {
	cmdTpl := BuildCommandTemplate(command)
	cleaned := normalizePolicyCWD(cwd)
	if cleaned == "" {
		return cmdTpl
	}
	return "cwd:" + cleaned + " && " + cmdTpl
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

// ContainsParentTraversal returns true if the string contains ".." as a path component.
func ContainsParentTraversal(s string) bool {
	return parentTraversalRE.MatchString(s)
}

// isRootOnly returns true if workspace_roots is effectively ["/"].
func isRootOnly(roots []string) bool {
	if len(roots) != 1 {
		return false
	}
	return strings.TrimSpace(roots[0]) == "/"
}

type workspaceProofStatus int

const (
	workspaceProofUnknown workspaceProofStatus = iota
	workspaceProofWithin
	workspaceProofOutside
)

type workspaceCheck struct {
	status workspaceProofStatus
	reason string
}

func normalizePolicyCWD(cwd string) string {
	cleaned := strings.TrimSpace(cwd)
	if cleaned == "" {
		return ""
	}
	return NormalizeRemotePath("", cleaned)
}

func evaluateWorkspaceAccess(cmd, cwd string, workspaceRoots []string) workspaceCheck {
	paths := extractAbsolutePaths(cmd)
	for _, p := range paths {
		if !IsWithinRoots(p, workspaceRoots) {
			return workspaceCheck{
				status: workspaceProofOutside,
				reason: "command targets path outside workspace_roots: " + p,
			}
		}
	}

	if isRootOnly(workspaceRoots) {
		return workspaceCheck{status: workspaceProofWithin}
	}

	if cwd == "" && ContainsParentTraversal(cmd) {
		return workspaceCheck{
			status: workspaceProofOutside,
			reason: "write command contains '..' with workspace_roots restriction",
		}
	}

	if !ContainsParentTraversal(cmd) && cwd == "" {
		return workspaceCheck{
			status: workspaceProofUnknown,
			reason: "cannot prove write targets stay within workspace_roots",
		}
	}

	analysis := analyzeWriteTargets(cmd, cwd, workspaceRoots)
	if analysis.status != workspaceProofUnknown {
		return analysis
	}

	if ContainsParentTraversal(cmd) {
		return workspaceCheck{
			status: workspaceProofUnknown,
			reason: "cannot prove write targets stay within workspace_roots from cwd: " + fallbackCWD(cwd),
		}
	}

	return workspaceCheck{
		status: workspaceProofUnknown,
		reason: "cannot prove write targets stay within workspace_roots from cwd: " + fallbackCWD(cwd),
	}
}

func fallbackCWD(cwd string) string {
	if cwd == "" {
		return "/"
	}
	return cwd
}

func analyzeWriteTargets(cmd, cwd string, workspaceRoots []string) workspaceCheck {
	if cwd == "" {
		return workspaceCheck{status: workspaceProofUnknown}
	}

	tokens, ok := tokenizeShellCommand(cmd)
	if !ok || len(tokens) == 0 {
		return workspaceCheck{
			status: workspaceProofUnknown,
			reason: "cannot prove write targets stay within workspace_roots from cwd: " + fallbackCWD(cwd),
		}
	}
	for _, tok := range tokens {
		if isShellControlToken(tok) {
			return workspaceCheck{
				status: workspaceProofUnknown,
				reason: "cannot prove write targets stay within workspace_roots from cwd: " + fallbackCWD(cwd),
			}
		}
	}

	verbIdx := 0
	for verbIdx < len(tokens) && isEnvAssignment(tokens[verbIdx]) {
		verbIdx++
	}
	verbIdx = skipSudoPrefix(tokens[verbIdx:]) + verbIdx
	if verbIdx >= len(tokens) {
		return workspaceCheck{status: workspaceProofUnknown, reason: "cannot prove write targets stay within workspace_roots from cwd: " + fallbackCWD(cwd)}
	}
	verb := strings.ToLower(path.Base(strings.Trim(tokens[verbIdx], `"'`)))
	args := tokens[verbIdx+1:]
	targets, ok := extractWriteTargets(verb, args)
	if !ok || len(targets) == 0 {
		return workspaceCheck{
			status: workspaceProofUnknown,
			reason: "cannot prove write targets stay within workspace_roots from cwd: " + fallbackCWD(cwd),
		}
	}

	for _, target := range targets {
		resolved, ok := resolveWriteTarget(target, cwd)
		if !ok {
			return workspaceCheck{
				status: workspaceProofUnknown,
				reason: "cannot prove write targets stay within workspace_roots from cwd: " + fallbackCWD(cwd),
			}
		}
		if !IsWithinRoots(resolved, workspaceRoots) {
			return workspaceCheck{
				status: workspaceProofOutside,
				reason: "command targets path outside workspace_roots: " + resolved,
			}
		}
	}
	return workspaceCheck{status: workspaceProofWithin}
}

func resolveWriteTarget(target, cwd string) (string, bool) {
	trimmed := strings.TrimSpace(strings.Trim(target, `"'`))
	if trimmed == "" || trimmed == "-" {
		return "", false
	}
	if strings.HasPrefix(trimmed, "~") || strings.ContainsAny(trimmed, "$*?[]{}()`") {
		return "", false
	}
	return NormalizeRemotePath(trimmed, cwd), true
}

func extractWriteTargets(verb string, args []string) ([]string, bool) {
	switch verb {
	case "rm", "mkdir", "rmdir", "touch", "truncate":
		targets := nonFlagArgs(args)
		return targets, len(targets) > 0
	case "cp", "mv", "ln":
		targets := nonFlagArgs(args)
		return targets, len(targets) >= 2
	case "tee":
		targets := nonFlagArgs(args)
		return targets, len(targets) > 0
	case "sed":
		return extractSedTargets(args)
	case "chmod", "chown":
		targets := nonFlagArgs(args)
		if len(targets) < 2 {
			return nil, false
		}
		return targets[1:], true
	case "echo", "printf", "cat":
		return extractRedirectTargets(args)
	default:
		return nil, false
	}
}

func nonFlagArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if isShellControlToken(arg) {
			return nil
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			continue
		}
		out = append(out, arg)
	}
	return out
}

func extractSedTargets(args []string) ([]string, bool) {
	targets := []string{}
	hasInPlace := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if isShellControlToken(arg) {
			return nil, false
		}
		if arg == "-i" || strings.HasPrefix(arg, "-i") {
			hasInPlace = true
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			continue
		}
		targets = append(targets, arg)
	}
	if !hasInPlace || len(targets) == 0 {
		return nil, false
	}
	return targets[1:], len(targets[1:]) > 0
}

func extractRedirectTargets(args []string) ([]string, bool) {
	targets := []string{}
	for i := 0; i < len(args); i++ {
		if args[i] != ">" && args[i] != ">>" {
			continue
		}
		if i+1 >= len(args) {
			return nil, false
		}
		targets = append(targets, args[i+1])
		i++
	}
	return targets, len(targets) > 0
}

func tokenizeShellCommand(cmd string) ([]string, bool) {
	var (
		tokens []string
		buf    strings.Builder
		quote  rune
		escape bool
	)

	flush := func() {
		if buf.Len() == 0 {
			return
		}
		tokens = append(tokens, buf.String())
		buf.Reset()
	}

	for _, r := range cmd {
		switch {
		case escape:
			buf.WriteRune(r)
			escape = false
		case quote == '\'':
			if r == '\'' {
				quote = 0
			} else {
				buf.WriteRune(r)
			}
		case quote == '"':
			if r == '"' {
				quote = 0
			} else if r == '\\' {
				escape = true
			} else {
				buf.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == '\\':
			escape = true
		case r == ' ' || r == '\t' || r == '\n':
			flush()
		case r == '>' || r == '<' || r == '|' || r == ';' || r == '&':
			flush()
			tok := string(r)
			if (r == '>' || r == '|' || r == '&') && len(tokens) > 0 && tokens[len(tokens)-1] == tok {
				tokens[len(tokens)-1] += tok
			} else {
				tokens = append(tokens, tok)
			}
		default:
			buf.WriteRune(r)
		}
	}
	if escape || quote != 0 {
		return nil, false
	}
	flush()
	return tokens, true
}

func isShellControlToken(tok string) bool {
	switch tok {
	case ">", ">>", "<", "<<", "|", "||", "&", "&&", ";":
		return true
	default:
		return false
	}
}

func isEnvAssignment(tok string) bool {
	if strings.HasPrefix(tok, "=") || !strings.Contains(tok, "=") {
		return false
	}
	left, _, _ := strings.Cut(tok, "=")
	return left != "" && !strings.ContainsAny(left, "/-")
}
