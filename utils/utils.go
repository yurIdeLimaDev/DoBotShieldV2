package utils

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func GetRealIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || ip == "" {
		return r.RemoteAddr
	}
	return ip
}

func GetClientIP(r *http.Request, trustedProxies []string) string {
	directIP := GetRealIP(r)
	if !IsTrustedProxy(directIP, trustedProxies) {
		return directIP
	}

	forwardedIPs := getForwardedIPs(r)
	if len(forwardedIPs) == 0 {
		return directIP
	}

	for i := len(forwardedIPs) - 1; i >= 0; i-- {
		if !IsTrustedProxy(forwardedIPs[i], trustedProxies) {
			return forwardedIPs[i]
		}
	}

	return forwardedIPs[0]
}

func IsTrustedProxy(ip string, trustedProxies []string) bool {
	parsedIP := parseIPToken(ip)
	if parsedIP == nil {
		return false
	}

	for _, trusted := range trustedProxies {
		trusted = strings.TrimSpace(trusted)
		if trusted == "" {
			continue
		}

		if strings.Contains(trusted, "/") {
			_, network, err := net.ParseCIDR(trusted)
			if err == nil && network.Contains(parsedIP) {
				return true
			}
			continue
		}

		trustedIP := parseIPToken(trusted)
		if trustedIP != nil && trustedIP.Equal(parsedIP) {
			return true
		}
	}
	return false
}

func getForwardedIPs(r *http.Request) []string {
	if xForwardedFor := parseXForwardedFor(r.Header.Values("X-Forwarded-For")); len(xForwardedFor) > 0 {
		return xForwardedFor
	}
	return parseForwardedHeader(r.Header.Values("Forwarded"))
}

func parseXForwardedFor(values []string) []string {
	var ips []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if ip := parseIPToken(part); ip != nil {
				ips = append(ips, ip.String())
			}
		}
	}
	return ips
}

func parseForwardedHeader(values []string) []string {
	var ips []string
	for _, value := range values {
		for _, element := range strings.Split(value, ",") {
			for _, param := range strings.Split(element, ";") {
				key, rawValue, found := strings.Cut(param, "=")
				if !found || !strings.EqualFold(strings.TrimSpace(key), "for") {
					continue
				}
				if ip := parseIPToken(rawValue); ip != nil {
					ips = append(ips, ip.String())
				}
			}
		}
	}
	return ips
}

func parseIPToken(value string) net.IP {
	token := strings.TrimSpace(value)
	token = strings.Trim(token, `"`)
	if token == "" || strings.EqualFold(token, "unknown") || strings.HasPrefix(token, "_") {
		return nil
	}

	if strings.HasPrefix(token, "[") {
		if end := strings.Index(token, "]"); end > 0 {
			token = token[1:end]
		}
	} else if host, _, err := net.SplitHostPort(token); err == nil {
		token = host
	}

	return net.ParseIP(token)
}

func LogEvent(eventType, ip, details, path string) {
	log.Printf("[%s] ip=%q path=%q details=%q", eventType, truncateLogValue(ip), truncateLogValue(path), truncateLogValue(details))
}

func GetOrCreateRequestID(r *http.Request) string {
	for _, header := range []string{"X-Request-ID", "X-Correlation-ID"} {
		if requestID := sanitizeRequestID(r.Header.Get(header)); requestID != "" {
			return requestID
		}
	}
	return NewRequestID()
}

func NewRequestID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	return strings.ToLower(strconv.FormatInt(time.Now().UnixNano(), 16))
}

func LogEventWithRequestID(requestID, eventType, ip, details, path string) {
	log.Printf("[%s] request_id=%q ip=%q path=%q details=%q", eventType, truncateLogValue(requestID), truncateLogValue(ip), truncateLogValue(path), truncateLogValue(details))
}

func LogAccess(requestID, method, path, ip string) {
	log.Printf("[ACCESS] request_id=%q method=%q path=%q ip=%q", truncateLogValue(requestID), truncateLogValue(method), truncateLogValue(path), truncateLogValue(ip))
}

func truncateLogValue(value string) string {
	const maxLogFieldBytes = 2048
	if len(value) <= maxLogFieldBytes {
		return value
	}
	return value[:maxLogFieldBytes] + "...(truncated)"
}

func sanitizeRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}

	for _, r := range value {
		valid := (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-' || r == ':'
		if !valid {
			return ""
		}
	}
	return value
}
