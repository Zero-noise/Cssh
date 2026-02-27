package security

import (
	"path"
	"regexp"
	"strings"

	"cssh/internal/model"
)

// highRiskPatterns is kept for backward compatibility with ClassifyCommandRisk.
var highRiskPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(shutdown|reboot|poweroff|halt)\b`),
	regexp.MustCompile(`(?i)\binit\s+(0|6)\b`),
	regexp.MustCompile(`(?i)\bdd\s+if=`),
	regexp.MustCompile(`(?i)\bdd\s+of=/dev/`),
	regexp.MustCompile(`(?i)\bmkfs\b`),
	regexp.MustCompile(`(?i)\b(wipefs|fdisk|sfdisk|parted)\b`),
	regexp.MustCompile(`(?i)\buseradd\b|\busermod\b|\buserdel\b`),
	regexp.MustCompile(`(?i)\bsystemctl\s+(stop|disable|mask)\b`),
	regexp.MustCompile(`(?i)\bchmod\s+777\b`),
	regexp.MustCompile(`(?i)\bchown\s+-R\s+root\b`),
	regexp.MustCompile(`:\(\)\s*\{\s*:\|:\s*&\s*\};:`),
}

// denyAlwaysPatterns: fork bomb only (rm -rf / and critical find -delete are handled by dedicated functions).
var denyAlwaysPatterns = []*regexp.Regexp{
	regexp.MustCompile(`:\(\)\s*\{\s*:\|:\s*&\s*\};:`),
}

// denyNeedApprovePatterns: dangerous but potentially legitimate commands requiring out-of-band approval.
var denyNeedApprovePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bdd\s+of=/dev/`),
	regexp.MustCompile(`(?i)\bmkfs\b`),
	regexp.MustCompile(`(?i)\b(wipefs|fdisk|sfdisk|parted)\b`),
	regexp.MustCompile(`(?i)\b(shutdown|reboot|poweroff|halt)\b`),
	regexp.MustCompile(`(?i)\binit\s+(0|6)\b`),
}

// denyNoneHighRiskPatterns: L2 for audit purposes, auto-execute.
var denyNoneHighRiskPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bdd\s+if=`),
	regexp.MustCompile(`(?i)\buseradd\b|\busermod\b|\buserdel\b`),
	regexp.MustCompile(`(?i)\bsystemctl\s+(stop|disable|mask)\b`),
	regexp.MustCompile(`(?i)\bchmod\s+777\b`),
	regexp.MustCompile(`(?i)\bchown\s+-R\s+root\b`),
}

// shutdown/reboot patterns used for AllowReboot override.
var shutdownPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(shutdown|reboot|poweroff|halt)\b`),
	regexp.MustCompile(`(?i)\binit\s+(0|6)\b`),
}

// disk operation patterns used for AllowDiskOps override.
var diskOpsPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bdd\s+of=/dev/`),
	regexp.MustCompile(`(?i)\bmkfs\b`),
	regexp.MustCompile(`(?i)\b(wipefs|fdisk|sfdisk|parted)\b`),
}

// DenyClassification holds the result of ClassifyDenyClass.
type DenyClassification struct {
	DenyClass model.DenyClass
	RiskLevel model.RiskLevel
	Reason    string
	IsUpgrade bool // true when DenyNeedApprove is set by maxAutoRisk policy, not by pattern match
}

var writePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(tee|sed\s+-i|truncate|touch|mv|cp|mkdir|rmdir|chmod|chown|ln|rm)\b`),
	regexp.MustCompile(`(?i)\bfind\b.*\s-delete\b`),
	regexp.MustCompile(`(^|\s)>\s*`),
	regexp.MustCompile(`(^|\s)>>\s*`),
	regexp.MustCompile(`(?i)\b(cat|echo)\b.*(>|>>)\s*`),
	regexp.MustCompile(`(?i)\bgit\s+(commit|push|rebase|reset|clean)\b`),
	regexp.MustCompile(`(?i)\bpatch\b`),
}

var criticalFindDeleteRoots = []string{
	"/",
	"/bin",
	"/sbin",
	"/etc",
	"/usr",
	"/lib",
	"/lib64",
	"/boot",
	"/var",
	"/opt",
	"/root",
}

func ClassifyCommandRisk(cmd string) (model.RiskLevel, string) {
	normalized := strings.TrimSpace(cmd)
	if normalized == "" {
		return model.RiskL0, "empty command"
	}
	if isCriticalRmRoot(normalized) {
		return model.RiskL2, "matched high risk policy"
	}
	if risk, reason, ok := classifyFindDeleteRisk(normalized); ok {
		return risk, reason
	}
	for _, pat := range highRiskPatterns {
		if pat.MatchString(normalized) {
			return model.RiskL2, "matched high risk policy"
		}
	}
	for _, pat := range writePatterns {
		if pat.MatchString(normalized) {
			return model.RiskL1, "matched write operation policy"
		}
	}
	return model.RiskL0, "read-only command"
}

func isCriticalRmRoot(command string) bool {
	tokens := strings.Fields(strings.ToLower(strings.TrimSpace(command)))
	if len(tokens) < 2 {
		return false
	}
	i := 0
	if tokens[i] == "sudo" {
		i++
		if i >= len(tokens) {
			return false
		}
	}
	if path.Base(tokens[i]) != "rm" {
		return false
	}
	i++
	hasRecursive := false
	hasForce := false
	for i < len(tokens) {
		tok := tokens[i]
		if tok == "--" {
			i++
			break
		}
		if strings.HasPrefix(tok, "--") {
			switch tok {
			case "--recursive":
				hasRecursive = true
			case "--force":
				hasForce = true
			}
			i++
			continue
		}
		if strings.HasPrefix(tok, "-") && tok != "-" {
			for _, ch := range tok[1:] {
				if ch == 'r' || ch == 'R' {
					hasRecursive = true
				}
				if ch == 'f' {
					hasForce = true
				}
			}
			i++
			continue
		}
		break
	}
	if !hasRecursive || !hasForce {
		return false
	}
	for ; i < len(tokens); i++ {
		target := strings.Trim(tokens[i], `"'`)
		switch target {
		case "/", "/*", "/.", "/..":
			return true
		}
		if strings.HasPrefix(target, "/*") {
			return true
		}
	}
	return false
}

func classifyFindDeleteRisk(command string) (model.RiskLevel, string, bool) {
	tokens := strings.Fields(strings.TrimSpace(command))
	if len(tokens) == 0 {
		return model.RiskL0, "", false
	}
	i := skipSudoPrefix(tokens)
	if i >= len(tokens) {
		return model.RiskL0, "", false
	}
	if !strings.EqualFold(path.Base(strings.Trim(tokens[i], `"'`)), "find") {
		return model.RiskL0, "", false
	}
	i++
	hasDelete := false
	for j := i; j < len(tokens); j++ {
		if strings.EqualFold(strings.Trim(tokens[j], `"'`), "-delete") {
			hasDelete = true
			break
		}
	}
	if !hasDelete {
		return model.RiskL0, "", false
	}

	startPaths := parseFindStartPaths(tokens, i)
	for _, p := range startPaths {
		if isCriticalFindDeletePath(p) {
			return model.RiskL2, "matched high risk policy", true
		}
	}
	return model.RiskL1, "matched write operation policy", true
}

func skipSudoPrefix(tokens []string) int {
	i := 0
	if i >= len(tokens) || !strings.EqualFold(tokens[i], "sudo") {
		return i
	}
	i++
	for i < len(tokens) {
		tok := tokens[i]
		if tok == "--" {
			i++
			break
		}
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			break
		}
		if tokenNeedsValue(tok) {
			i += 2
			continue
		}
		i++
	}
	if i > len(tokens) {
		return len(tokens)
	}
	return i
}

func tokenNeedsValue(tok string) bool {
	switch strings.ToLower(tok) {
	case "-u", "-g", "-h", "-r", "-t", "-p", "-c":
		return true
	default:
		return false
	}
}

func parseFindStartPaths(tokens []string, start int) []string {
	paths := []string{}
	i := start
	for i < len(tokens) {
		tok := strings.Trim(tokens[i], `"'`)
		if tok == "" {
			i++
			continue
		}
		if tok == "--" {
			i++
			break
		}
		if !isFindPrePathOption(tok) {
			break
		}
		if (tok == "-D" || tok == "-O") && i+1 < len(tokens) {
			i += 2
			continue
		}
		i++
	}
	for ; i < len(tokens); i++ {
		tok := strings.Trim(tokens[i], `"'`)
		if tok == "" {
			continue
		}
		if isFindExprToken(tok) {
			break
		}
		paths = append(paths, tok)
	}
	if len(paths) == 0 {
		return []string{"."}
	}
	return paths
}

func isFindExprToken(tok string) bool {
	return tok == "!" || tok == "(" || tok == ")" || tok == "," || strings.HasPrefix(tok, "-")
}

func isFindPrePathOption(tok string) bool {
	return tok == "-H" ||
		tok == "-L" ||
		tok == "-P" ||
		tok == "-D" ||
		tok == "-O" ||
		strings.HasPrefix(tok, "-D") ||
		strings.HasPrefix(tok, "-O")
}

func isCriticalFindDeletePath(p string) bool {
	p = strings.TrimSpace(strings.Trim(p, `"'`))
	if p == "" || !strings.HasPrefix(p, "/") {
		return false
	}
	// Drop wildcard suffix, then normalize to compare against critical roots.
	if idx := strings.IndexAny(p, "*?["); idx >= 0 {
		p = strings.TrimRight(p[:idx], "/")
		if p == "" {
			p = "/"
		}
	}
	clean := path.Clean(p)
	if clean == "/" {
		return true
	}
	for _, root := range criticalFindDeleteRoots {
		if root == "/" {
			continue
		}
		if clean == root || strings.HasPrefix(clean, root+"/") {
			return true
		}
	}
	return false
}

// ClassifyDenyClass determines the deny class of a command considering profile policy fields.
func ClassifyDenyClass(cmd string, maxAutoRisk string, allowReboot, allowDiskOps bool, denyPatterns []string) DenyClassification {
	normalized := strings.TrimSpace(cmd)
	if normalized == "" {
		return DenyClassification{DenyClass: model.DenyNone, RiskLevel: model.RiskL0, Reason: "empty command"}
	}

	// Unwrap shell wrappers and classify all variants, taking highest severity.
	variants := UnwrapShellWrappers(normalized)
	best := classifyDenyClassSingle(normalized, maxAutoRisk, allowReboot, allowDiskOps, denyPatterns)
	for _, v := range variants {
		if v == normalized {
			continue
		}
		c := classifyDenyClassSingle(v, maxAutoRisk, allowReboot, allowDiskOps, denyPatterns)
		if denyClassSeverity(c.DenyClass) > denyClassSeverity(best.DenyClass) {
			best = c
		} else if denyClassSeverity(c.DenyClass) == denyClassSeverity(best.DenyClass) && riskSeverity(c.RiskLevel) > riskSeverity(best.RiskLevel) {
			best = c
		}
	}
	return best
}

func classifyDenyClassSingle(cmd string, maxAutoRisk string, allowReboot, allowDiskOps bool, denyPatterns []string) DenyClassification {
	// DenyAlways: fork bomb
	for _, pat := range denyAlwaysPatterns {
		if pat.MatchString(cmd) {
			return DenyClassification{DenyClass: model.DenyAlways, RiskLevel: model.RiskL2, Reason: "catastrophic command (fork bomb)"}
		}
	}
	// DenyAlways: critical rm -rf /
	if isCriticalRmRoot(cmd) {
		return DenyClassification{DenyClass: model.DenyAlways, RiskLevel: model.RiskL2, Reason: "catastrophic command (rm -rf /)"}
	}
	// DenyAlways: critical find -delete on system paths
	if risk, reason, ok := classifyFindDeleteRisk(cmd); ok && risk == model.RiskL2 {
		return DenyClassification{DenyClass: model.DenyAlways, RiskLevel: model.RiskL2, Reason: reason}
	}

	// DenyNeedApprove patterns (with profile overrides)
	for _, pat := range denyNeedApprovePatterns {
		if !pat.MatchString(cmd) {
			continue
		}
		// Check if this is a shutdown/reboot command and AllowReboot is true
		if allowReboot && matchesAny(cmd, shutdownPatterns) {
			return DenyClassification{DenyClass: model.DenyNone, RiskLevel: model.RiskL2, Reason: "shutdown/reboot allowed by profile"}
		}
		// Check if this is a disk ops command and AllowDiskOps is true
		if allowDiskOps && matchesAny(cmd, diskOpsPatterns) {
			return DenyClassification{DenyClass: model.DenyNone, RiskLevel: model.RiskL2, Reason: "disk operation allowed by profile"}
		}
		return DenyClassification{DenyClass: model.DenyNeedApprove, RiskLevel: model.RiskL2, Reason: "dangerous command requires approval"}
	}

	// User deny patterns → DenyNeedApprove
	for _, pattern := range denyPatterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(cmd) {
			return DenyClassification{DenyClass: model.DenyNeedApprove, RiskLevel: model.RiskL2, Reason: "matched user deny pattern: " + pattern}
		}
	}

	// denyNoneHighRiskPatterns → L2, DenyNone
	for _, pat := range denyNoneHighRiskPatterns {
		if pat.MatchString(cmd) {
			risk := model.RiskL2
			dc := model.DenyNone
			isUpgrade := false
			// If maxAutoRisk="L1" and risk is L2 → upgrade to DenyNeedApprove
			if strings.EqualFold(strings.TrimSpace(maxAutoRisk), "L1") {
				dc = model.DenyNeedApprove
				isUpgrade = true
			}
			return DenyClassification{DenyClass: dc, RiskLevel: risk, Reason: "matched high risk policy", IsUpgrade: isUpgrade}
		}
	}

	// find -delete on non-critical paths → L1, DenyNone
	if risk, reason, ok := classifyFindDeleteRisk(cmd); ok {
		dc := model.DenyNone
		isUpgrade := false
		if strings.EqualFold(strings.TrimSpace(maxAutoRisk), "L1") && risk == model.RiskL2 {
			dc = model.DenyNeedApprove
			isUpgrade = true
		}
		return DenyClassification{DenyClass: dc, RiskLevel: risk, Reason: reason, IsUpgrade: isUpgrade}
	}

	// Write patterns → L1
	for _, pat := range writePatterns {
		if pat.MatchString(cmd) {
			risk := model.RiskL1
			dc := model.DenyNone
			if strings.EqualFold(strings.TrimSpace(maxAutoRisk), "L1") {
				// L1 write commands stay DenyNone (L1 threshold means only L2 gets upgraded)
			}
			return DenyClassification{DenyClass: dc, RiskLevel: risk, Reason: "matched write operation policy"}
		}
	}

	// Default: L0, DenyNone
	return DenyClassification{DenyClass: model.DenyNone, RiskLevel: model.RiskL0, Reason: "read-only command"}
}

// UnwrapShellWrappers detects common shell wrappers and returns inner commands.
// Best-effort. Does not cover base64/hex encoding, heredocs, or variable expansion.
func UnwrapShellWrappers(cmd string) []string {
	result := []string{cmd}
	inner := unwrapOnce(cmd)
	for _, i := range inner {
		if i != cmd {
			result = append(result, i)
			// One level of recursion only
			for _, j := range unwrapOnce(i) {
				if j != i && j != cmd {
					result = append(result, j)
				}
			}
		}
	}
	return result
}

var (
	bashCRE = regexp.MustCompile(`(?:^|\s)(?:bash|sh)\s+-c\s+`)
	evalRE  = regexp.MustCompile(`(?:^|\s)eval\s+`)
	pipeSH  = regexp.MustCompile(`\|\s*(?:bash|sh)\s*$`)
)

func unwrapOnce(cmd string) []string {
	var results []string
	trimmed := strings.TrimSpace(cmd)

	// bash -c '...' / sh -c "..."
	if bashCRE.MatchString(trimmed) {
		loc := bashCRE.FindStringIndex(trimmed)
		if loc != nil {
			rest := trimmed[loc[1]:]
			if inner := extractQuotedOrFirstArg(rest); inner != "" {
				results = append(results, inner)
			}
		}
	}

	// eval "..."
	if evalRE.MatchString(trimmed) {
		loc := evalRE.FindStringIndex(trimmed)
		if loc != nil {
			rest := trimmed[loc[1]:]
			if inner := extractQuotedOrFirstArg(rest); inner != "" {
				results = append(results, inner)
			}
		}
	}

	// echo "..." | bash / | sh
	if pipeSH.MatchString(trimmed) {
		loc := pipeSH.FindStringIndex(trimmed)
		if loc != nil {
			before := strings.TrimSpace(trimmed[:loc[0]])
			// Try to extract the echoed content
			if strings.HasPrefix(before, "echo ") {
				content := strings.TrimSpace(strings.TrimPrefix(before, "echo"))
				if inner := stripQuotes(content); inner != "" {
					results = append(results, inner)
				}
			}
		}
	}

	return results
}

func extractQuotedOrFirstArg(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return ""
	}
	if s[0] == '\'' {
		end := strings.Index(s[1:], "'")
		if end >= 0 {
			return s[1 : end+1]
		}
	}
	if s[0] == '"' {
		end := strings.Index(s[1:], "\"")
		if end >= 0 {
			return s[1 : end+1]
		}
	}
	// Unquoted: take until end of string
	return s
}

func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func matchesAny(cmd string, patterns []*regexp.Regexp) bool {
	for _, p := range patterns {
		if p.MatchString(cmd) {
			return true
		}
	}
	return false
}

func denyClassSeverity(dc model.DenyClass) int {
	switch dc {
	case model.DenyAlways:
		return 2
	case model.DenyNeedApprove:
		return 1
	default:
		return 0
	}
}

func riskSeverity(r model.RiskLevel) int {
	switch r {
	case model.RiskL2:
		return 2
	case model.RiskL1:
		return 1
	default:
		return 0
	}
}
