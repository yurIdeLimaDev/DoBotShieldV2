package blocklist

import (
	"net"
	"strings"
)

// List holds IP addresses and CIDR networks that are permanently denied.
type List struct {
	networks []*net.IPNet
	addrs    map[string]struct{}
}

// New builds a blocklist. Invalid entries are ignored.
func New(entries []string) *List {
	l := &List{addrs: make(map[string]struct{})}
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, network, err := net.ParseCIDR(entry); err == nil {
				l.networks = append(l.networks, network)
			}
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			l.addrs[ip.String()] = struct{}{}
		}
	}
	return l
}

// Contains checks exact IP addresses before CIDR networks for the common case.
func (l *List) Contains(ipStr string) bool {
	if len(l.networks) == 0 && len(l.addrs) == 0 {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	if _, ok := l.addrs[ip.String()]; ok {
		return true
	}
	for _, network := range l.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
