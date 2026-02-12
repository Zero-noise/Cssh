package security

import (
	"path"
	"regexp"
	"strings"

	"cssh/internal/model"
)

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
