package waf

import (
	"mime"
	"net/http"
	"strings"
	"unicode"
)

// ProtocolLimits bounds parsing work performed before application-level rules.
type ProtocolLimits struct {
	MaxURLLength   int
	MaxHeaderBytes int
	MaxHeaderCount int
}

// Violation describes an HTTP or body-framing condition that cannot be safely
// forwarded to a potentially more permissive backend parser.
type Violation struct {
	Details string
	Rule    string
	Status  int
}

// CheckProtocol rejects ambiguous framing, malformed metadata, and unusually
// large request targets before the reverse proxy forwards the request.
func CheckProtocol(r *http.Request, limits ProtocolLimits) *Violation {
	if r == nil {
		return &Violation{"PROTOCOL_VIOLATION in Request", "PROTO-001", http.StatusBadRequest}
	}

	if limits.MaxURLLength > 0 && len(r.URL.RequestURI()) > limits.MaxURLLength {
		return &Violation{"PROTOCOL_VIOLATION in Request Target", "PROTO-002", http.StatusRequestURITooLong}
	}
	if !validHostSyntax(r.Host) {
		return &Violation{"PROTOCOL_VIOLATION in Host", "PROTO-003", http.StatusBadRequest}
	}

	headerCount, headerBytes := 0, len(r.Host)
	for name, values := range r.Header {
		if !validHeaderName(name) {
			return &Violation{"PROTOCOL_VIOLATION in Header Name", "PROTO-004", http.StatusBadRequest}
		}
		for _, value := range values {
			headerCount++
			headerBytes += len(name) + len(value) + 4
			if containsInvalidHeaderValue(value) {
				return &Violation{"PROTOCOL_VIOLATION in Header " + name, "PROTO-005", http.StatusBadRequest}
			}
		}
	}
	if limits.MaxHeaderCount > 0 && headerCount > limits.MaxHeaderCount {
		return &Violation{"PROTOCOL_VIOLATION in Headers", "PROTO-006", http.StatusRequestHeaderFieldsTooLarge}
	}
	if limits.MaxHeaderBytes > 0 && headerBytes > limits.MaxHeaderBytes {
		return &Violation{"PROTOCOL_VIOLATION in Headers", "PROTO-007", http.StatusRequestHeaderFieldsTooLarge}
	}

	for _, singleton := range []string{
		"Content-Type", "Content-Encoding", "Expect", "Upgrade", "Origin",
		"Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions",
	} {
		if len(r.Header.Values(singleton)) > 1 {
			return &Violation{"PROTOCOL_VIOLATION in Header " + singleton, "PROTO-008", http.StatusBadRequest}
		}
	}

	if contentType := strings.TrimSpace(r.Header.Get("Content-Type")); contentType != "" {
		if _, _, err := mime.ParseMediaType(contentType); err != nil {
			return &Violation{"PROTOCOL_VIOLATION in Header Content-Type", "PROTO-009", http.StatusUnsupportedMediaType}
		}
	}

	if encoding := strings.TrimSpace(r.Header.Get("Content-Encoding")); strings.Contains(encoding, ",") {
		return &Violation{"PROTOCOL_VIOLATION in Header Content-Encoding", "PROTO-010", http.StatusUnsupportedMediaType}
	}

	if len(r.TransferEncoding) > 0 {
		if len(r.TransferEncoding) != 1 || !strings.EqualFold(r.TransferEncoding[0], "chunked") || r.ContentLength >= 0 {
			return &Violation{"PROTOCOL_VIOLATION in Message Framing", "PROTO-011", http.StatusBadRequest}
		}
	}

	if expect := strings.TrimSpace(r.Header.Get("Expect")); expect != "" && !strings.EqualFold(expect, "100-continue") {
		return &Violation{"PROTOCOL_VIOLATION in Header Expect", "PROTO-012", http.StatusExpectationFailed}
	}

	for _, token := range splitHeaderTokens(r.Header.Values("Connection")) {
		switch strings.ToLower(token) {
		case "content-length", "transfer-encoding", "host", "content-type", "content-encoding", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto":
			return &Violation{"PROTOCOL_VIOLATION in Header Connection", "PROTO-013", http.StatusBadRequest}
		}
	}

	upgrade := strings.TrimSpace(r.Header.Get("Upgrade"))
	connectionUpgrade := hasHeaderToken(r.Header.Values("Connection"), "upgrade")
	if upgrade != "" || connectionUpgrade {
		if !connectionUpgrade || !strings.EqualFold(upgrade, "websocket") {
			return &Violation{"PROTOCOL_VIOLATION in Upgrade", "PROTO-014", http.StatusBadRequest}
		}
		if !strings.EqualFold(r.Method, http.MethodGet) || r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
			return &Violation{"PROTOCOL_VIOLATION in WebSocket Handshake", "PROTO-015", http.StatusBadRequest}
		}
	}

	return nil
}

func validHostSyntax(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || strings.ContainsAny(host, "\r\n\t /\\@") {
		return false
	}
	for _, r := range host {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			return false
		}
	}
	return true
}

func containsInvalidHeaderValue(value string) bool {
	for _, r := range value {
		if r == '\r' || r == '\n' || r == 0 || (unicode.IsControl(r) && r != '\t') {
			return true
		}
	}
	return false
}

func splitHeaderTokens(values []string) []string {
	var tokens []string
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if clean := strings.TrimSpace(token); clean != "" {
				tokens = append(tokens, clean)
			}
		}
	}
	return tokens
}

func hasHeaderToken(values []string, target string) bool {
	for _, token := range splitHeaderTokens(values) {
		if strings.EqualFold(token, target) {
			return true
		}
	}
	return false
}
