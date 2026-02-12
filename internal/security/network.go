package security

import (
	"net"
	"strings"
)

func IsPrivateOrLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsPrivate() || ip.IsLoopback()
	}
	host = strings.ToLower(strings.TrimSpace(host))
	// DNS names are treated as private-safe only for known VPN/local suffixes.
	for _, suffix := range []string{".local", ".lan", ".internal", ".ts.net"} {
		if len(host) > len(suffix) && host[len(host)-len(suffix):] == suffix {
			return true
		}
	}
	return false
}
