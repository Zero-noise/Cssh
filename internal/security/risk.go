package security

import (
	"regexp"
	"strings"

	"cssh/internal/model"
)

var highRiskPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+-rf\s+/`),
	regexp.MustCompile(`(?i)\bshutdown\b`),
	regexp.MustCompile(`(?i)\breboot\b`),
	regexp.MustCompile(`(?i)\bdd\s+if=`),
	regexp.MustCompile(`(?i)\bmkfs\b`),
	regexp.MustCompile(`(?i)\buseradd\b|\busermod\b|\buserdel\b`),
	regexp.MustCompile(`(?i)\bsystemctl\s+(stop|disable|mask)\b`),
	regexp.MustCompile(`(?i)\bchmod\s+777\b`),
	regexp.MustCompile(`(?i)\bchown\s+-R\s+root\b`),
}

var writePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(tee|sed\s+-i|truncate|touch|mv|cp|mkdir|rmdir|chmod|chown|ln)\b`),
	regexp.MustCompile(`(^|\s)>\s*`),
	regexp.MustCompile(`(^|\s)>>\s*`),
	regexp.MustCompile(`(?i)\b(cat|echo)\b.*(>|>>)\s*`),
	regexp.MustCompile(`(?i)\bgit\s+(commit|push|rebase|reset|clean)\b`),
	regexp.MustCompile(`(?i)\bpatch\b`),
}

func ClassifyCommandRisk(cmd string) (model.RiskLevel, string) {
	normalized := strings.TrimSpace(cmd)
	if normalized == "" {
		return model.RiskL0, "empty command"
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
