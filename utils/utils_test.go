package utils

import (
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestGetClientIPIgnoresSpoofedForwardedForFromUntrustedClient(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.10:49152"
	r.Header.Set("X-Forwarded-For", "198.51.100.20")

	got := GetClientIP(r, []string{"127.0.0.1", "::1"})
	if got != "203.0.113.10" {
		t.Fatalf("expected direct client IP, got %q", got)
	}
}

func TestGetOrCreateRequestIDRejectsPartiallyInvalidValues(t *testing.T) {
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("X-Request-ID", "trusted-prefix<script>")

	got := GetOrCreateRequestID(request)
	if got == "trusted-prefixscript" || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(got) {
		t.Fatalf("expected a fresh generated request ID, got %q", got)
	}
}

func TestGetClientIPUsesFirstUntrustedIPBeforeTrustedProxyChain(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:49152"
	r.Header.Set("X-Forwarded-For", "198.51.100.20, 10.0.0.4")

	got := GetClientIP(r, []string{"10.0.0.0/8"})
	if got != "198.51.100.20" {
		t.Fatalf("expected first untrusted forwarded IP, got %q", got)
	}
}

func TestGetClientIPSupportsForwardedHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:49152"
	r.Header.Set("Forwarded", `for=198.51.100.20;proto=https;by=10.0.0.5`)

	got := GetClientIP(r, []string{"10.0.0.0/8"})
	if got != "198.51.100.20" {
		t.Fatalf("expected RFC 7239 forwarded IP, got %q", got)
	}
}

func TestIsTrustedProxySupportsCIDR(t *testing.T) {
	if !IsTrustedProxy("10.10.20.30", []string{"10.0.0.0/8"}) {
		t.Fatalf("expected IP inside CIDR to be trusted")
	}
	if IsTrustedProxy("198.51.100.20", []string{"10.0.0.0/8"}) {
		t.Fatalf("expected IP outside CIDR to be untrusted")
	}
}
