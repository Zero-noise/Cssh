package util

import "strings"

func ShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	// Single-quote safe: 'abc' becomes 'abc'; with internal quote escaped as '\''.
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
