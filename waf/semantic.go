package waf

import (
	"encoding/binary"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var urlCandidatePattern = regexp.MustCompile(`(?i)(?:[a-z][a-z0-9+.-]{1,15}:)?//[^\s"'<>]+|(?:file|gopher|dict|ldap|smb):[^\s"'<>]+`)

func detectSemanticSSRF(input string) (bool, string) {
	for _, candidate := range urlCandidatePattern.FindAllString(input, 32) {
		candidate = strings.TrimRight(candidate, ".,;!?)]}\\")
		if strings.HasPrefix(candidate, "//") {
			candidate = "http:" + candidate
		}
		parsed, err := url.Parse(candidate)
		if err != nil {
			continue
		}
		scheme := strings.ToLower(parsed.Scheme)
		switch scheme {
		case "file", "gopher", "dict", "ldap", "ldaps", "smb":
			return true, "SSRF-SEMANTIC-SCHEME"
		case "http", "https", "ftp":
			// Continue with destination validation.
		default:
			continue
		}

		host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		if host == "localhost" || strings.HasSuffix(host, ".localhost") ||
			host == "metadata" || host == "metadata.google.internal" {
			return true, "SSRF-SEMANTIC-HOST"
		}
		if address, ok := parseFlexibleAddress(host); ok && unsafeSSRFAddress(address) {
			return true, "SSRF-SEMANTIC-IP"
		}
	}
	return false, ""
}

func parseFlexibleAddress(host string) (netip.Addr, bool) {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap(), true
	}

	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return netip.Addr{}, false
	}
	values := make([]uint64, len(parts))
	for index, part := range parts {
		value, ok := parseIPv4Number(part)
		if !ok {
			return netip.Addr{}, false
		}
		values[index] = value
	}

	var packed uint64
	switch len(values) {
	case 1:
		if values[0] > 0xffffffff {
			return netip.Addr{}, false
		}
		packed = values[0]
	case 2:
		if values[0] > 0xff || values[1] > 0xffffff {
			return netip.Addr{}, false
		}
		packed = values[0]<<24 | values[1]
	case 3:
		if values[0] > 0xff || values[1] > 0xff || values[2] > 0xffff {
			return netip.Addr{}, false
		}
		packed = values[0]<<24 | values[1]<<16 | values[2]
	case 4:
		for _, value := range values {
			if value > 0xff {
				return netip.Addr{}, false
			}
		}
		packed = values[0]<<24 | values[1]<<16 | values[2]<<8 | values[3]
	}

	var octets [4]byte
	binary.BigEndian.PutUint32(octets[:], uint32(packed))
	return netip.AddrFrom4(octets), true
}

func parseIPv4Number(value string) (uint64, bool) {
	if value == "" {
		return 0, false
	}
	base := 10
	digits := value
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base = 16
		digits = value[2:]
	} else if len(value) > 1 && value[0] == '0' {
		base = 8
		digits = value[1:]
	}
	if digits == "" {
		return 0, true
	}
	parsed, err := strconv.ParseUint(digits, base, 32)
	return parsed, err == nil
}

func unsafeSSRFAddress(address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	if address.IsLoopback() || address.IsPrivate() || address.IsUnspecified() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() {
		return true
	}
	if address.Is4() {
		shared, _ := netip.ParsePrefix("100.64.0.0/10")
		return shared.Contains(address)
	}
	return false
}
