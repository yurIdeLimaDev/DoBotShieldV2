package waf

import (
	"bytes"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type patternGroup struct {
	name     string
	patterns []*regexp.Regexp
}

var allGroups = []patternGroup{
	{"XSS", xssPatterns},
	{"SQLi", sqliPatterns},
	{"CMD_INJ", cmdPatterns},
	{"PATH_TRAVERSAL", traversalPatterns},
	{"XXE", xxePatterns},
	{"JNDI", jndiPatterns},
	{"SSRF", ssrfPatterns},
	{"NoSQLi", nosqlPatterns},
	{"SSTI", sstiPatterns},
	{"PROTOTYPE_POLLUTION", prototypePollutionPatterns},
	{"OPEN_REDIRECT", openRedirectPatterns},
	{"RFI", rfiPatterns},
	{"LDAPi", ldapPatterns},
	{"XPATHi", xpathPatterns},
	{"PHP_INJECTION", phpPatterns},
	{"UNSAFE_DESERIALIZATION", deserializationPatterns},
	{"HTTP_HEADER_INJECTION", headerInjectionPatterns},
}

var (
	unicodeEscapePattern = regexp.MustCompile(`(?i)(?:\\u|%u)([0-9a-f]{4})`)
	hexEscapePattern     = regexp.MustCompile(`(?i)\\x([0-9a-f]{2})`)
	blockCommentPattern  = regexp.MustCompile(`(?s)/\*.*?\*/`)
	inspectedHeaders     = []string{
		"Authorization",
		"Cookie",
		"Forwarded",
		"Referer",
		"User-Agent",
		"X-Forwarded-Host",
		"X-Original-URL",
		"X-Rewrite-URL",
	}
)

const (
	maxMultipartParts     = 64
	maxMultipartPartBytes = 256 * 1024
)

func fullyURLDecode(s string) string {
	decoded := s
	for i := 0; i < 5; i++ {
		d, err := url.QueryUnescape(decoded)
		if err != nil || d == decoded {
			break
		}
		decoded = d
	}
	return decoded
}

func analyzePayload(input string) (bool, string, string) {
	variants := buildInspectionVariants(input)
	if malicious, category, rule := analyzeVariantsWithGroups(variants, allGroups); malicious {
		return true, category, rule
	}
	for _, variant := range variants {
		if malicious, rule := detectSemanticSSRF(variant); malicious {
			return true, "SSRF", rule
		}
	}
	return false, "", ""
}

func analyzePayloadWithGroups(input string, groups []patternGroup) (bool, string, string) {
	return analyzeVariantsWithGroups(buildInspectionVariants(input), groups)
}

func analyzeVariantsWithGroups(variants []string, groups []patternGroup) (bool, string, string) {
	for _, t := range variants {
		for _, group := range groups {
			for _, p := range group.patterns {
				if p.MatchString(t) {
					return true, group.name, p.String()
				}
			}
		}
	}
	return false, "", ""
}

func buildInspectionVariants(input string) []string {
	var variants []string
	addVariant := func(value string) {
		if value == "" {
			return
		}
		for _, existing := range variants {
			if existing == value {
				return
			}
		}
		variants = append(variants, value)
	}

	decodedURL := fullyURLDecode(input)
	decodedHTML := fullyHTMLDecode(decodedURL)
	decodedEscapes := decodeScriptEscapes(decodedHTML)
	commentless := blockCommentPattern.ReplaceAllString(decodedEscapes, "")
	normalized := normalizeSeparators(commentless)
	compact := compactPayload(normalized)

	addVariant(input)
	addVariant(decodedURL)
	addVariant(decodedHTML)
	addVariant(decodedEscapes)
	addVariant(commentless)
	addVariant(normalized)
	addVariant(compact)

	return variants
}

func fullyHTMLDecode(s string) string {
	decoded := s
	for i := 0; i < 3; i++ {
		d := html.UnescapeString(decoded)
		if d == decoded {
			break
		}
		decoded = d
	}
	return decoded
}

func decodeScriptEscapes(s string) string {
	decoded := unicodeEscapePattern.ReplaceAllStringFunc(s, decodeUnicodeEscape)
	decoded = hexEscapePattern.ReplaceAllStringFunc(decoded, decodeHexEscape)
	return decoded
}

func decodeUnicodeEscape(match string) string {
	value, err := strconv.ParseInt(match[len(match)-4:], 16, 32)
	if err != nil {
		return match
	}
	return string(rune(value))
}

func decodeHexEscape(match string) string {
	value, err := strconv.ParseInt(match[len(match)-2:], 16, 8)
	if err != nil {
		return match
	}
	return string(rune(value))
}

func normalizeSeparators(s string) string {
	var b strings.Builder
	previousWasSpace := false

	for _, r := range s {
		if r == 0 {
			continue
		}
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			if !previousWasSpace {
				b.WriteByte(' ')
				previousWasSpace = true
			}
			continue
		}
		previousWasSpace = false
		b.WriteRune(r)
	}

	return strings.TrimSpace(b.String())
}

func compactPayload(s string) string {
	var b strings.Builder

	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(`<>/:;._-=$'"()\[]{}@`, r) {
			b.WriteRune(r)
		}
	}

	return b.String()
}

func CheckRequest(r *http.Request, bodyBytes []byte) (bool, string, string) {
	path := r.URL.EscapedPath()
	if path != "" && path != "/" {
		if mal, typ, pat := analyzePayload(path); mal {
			return true, typ + " in Path", pat
		}
	}

	if r.Host != "" {
		if mal, typ, pat := analyzePayload(r.Host); mal {
			return true, typ + " in Host", pat
		}
	}

	if r.URL.RawQuery != "" {
		if mal, typ, pat := analyzePayload(r.URL.RawQuery); mal {
			return true, typ + " in Query", pat
		}
		if _, err := url.ParseQuery(r.URL.RawQuery); err != nil {
			return true, "MALFORMED_QUERY in Query", "QUERY-001"
		}
	}

	for header, values := range r.Header {
		for _, value := range values {
			if mal, typ, pat := analyzePayloadWithGroups(value, []patternGroup{{"HTTP_HEADER_INJECTION", headerInjectionPatterns}}); mal {
				return true, typ + " in Header " + header, pat
			}
		}
	}

	for _, header := range inspectedHeaders {
		for _, value := range r.Header.Values(header) {
			if mal, typ, pat := analyzePayload(value); mal {
				return true, typ + " in Header " + header, pat
			}
		}
	}

	if len(bodyBytes) > 0 {
		if mal, typ, pat := inspectMultipart(r, bodyBytes); mal {
			return true, typ, pat
		}

		if mal, typ, pat := analyzePayload(string(bodyBytes)); mal {
			return true, typ + " in Body", pat
		}

		if mal, details, pat := inspectStructuredBody(r, bodyBytes); mal {
			return true, details, pat
		}
	}

	return false, "", ""
}

type ResponseOptions struct {
	DetectActiveXSS         bool
	DiagnosticsOnErrorsOnly bool
}

// CheckWebSocketClientMessage applies the request payload detectors to one
// complete client-to-server WebSocket message.
func CheckWebSocketClientMessage(message []byte) (bool, string, string) {
	if len(message) == 0 {
		return false, "", ""
	}
	if malicious, category, rule := analyzePayload(string(message)); malicious {
		return true, category + " in WebSocket Message", rule
	}
	return false, "", ""
}

// CheckWebSocketServerMessage applies response leak detectors to one complete
// server-to-client message. File leaks are always inspected. SQL and stack
// diagnostics can be enabled explicitly because WebSocket messages do not
// carry an HTTP status that distinguishes an error response.
func CheckWebSocketServerMessage(message []byte, detectActiveXSS, detectDiagnostics bool) (bool, string, string) {
	if len(message) == 0 {
		return false, "", ""
	}
	status := http.StatusOK
	if detectDiagnostics {
		status = http.StatusInternalServerError
	}
	response := &http.Response{StatusCode: status, Header: make(http.Header)}
	malicious, details, rule := CheckResponseWithOptions(response, message, ResponseOptions{
		DetectActiveXSS:         detectActiveXSS,
		DiagnosticsOnErrorsOnly: true,
	})
	if malicious {
		details = strings.Replace(details, "Response Body", "WebSocket Message", 1)
	}
	return malicious, details, rule
}

// CheckResponse retains the complete inspection API for callers that
// explicitly request it. The reverse proxy uses CheckResponseWithOptions so
// active scripts in legitimate HTML are not blocked unless enabled.
func CheckResponse(resp *http.Response, bodyBytes []byte) (bool, string, string) {
	return CheckResponseWithOptions(resp, bodyBytes, ResponseOptions{DetectActiveXSS: true})
}

func CheckResponseWithOptions(resp *http.Response, bodyBytes []byte, options ResponseOptions) (bool, string, string) {
	if len(bodyBytes) == 0 {
		return false, "", ""
	}

	groups := []patternGroup{{"RESPONSE_FILE_LEAK", responseFileLeakPatterns}}
	if !options.DiagnosticsOnErrorsOnly || resp == nil || resp.StatusCode >= http.StatusBadRequest {
		groups = append(groups,
			patternGroup{"RESPONSE_SQL_ERROR", responseSQLLeakPatterns},
			patternGroup{"RESPONSE_STACK_TRACE", responseStackTracePatterns},
		)
	}
	if options.DetectActiveXSS {
		groups = append(groups, patternGroup{"RESPONSE_XSS_PATTERN", responseXSSPatterns})
	}

	if mal, typ, pat := analyzePayloadWithGroups(string(bodyBytes), groups); mal {
		return true, typ + " in Response Body", pat
	}

	return false, "", ""
}

func inspectMultipart(r *http.Request, bodyBytes []byte) (bool, string, string) {
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		return false, "", ""
	}

	boundary := params["boundary"]
	if boundary == "" {
		return false, "", ""
	}

	reader := multipart.NewReader(bytes.NewReader(bodyBytes), boundary)
	for i := 0; i < maxMultipartParts; i++ {
		part, err := reader.NextPart()
		if err == io.EOF {
			return false, "", ""
		}
		if err != nil {
			return true, "MALFORMED_MULTIPART", err.Error()
		}

		if mal, typ, pat := inspectMultipartPart(part); mal {
			return true, typ, pat
		}
	}

	part, err := reader.NextPart()
	if err == io.EOF {
		return false, "", ""
	}
	if err != nil {
		return true, "MALFORMED_MULTIPART", err.Error()
	}
	_ = part.Close()
	return true, "MULTIPART_LIMIT", "too many multipart parts"
}

func inspectMultipartPart(part *multipart.Part) (bool, string, string) {
	defer part.Close()

	metadata := []string{part.FormName(), part.FileName(), part.Header.Get("Content-Type")}
	for _, value := range metadata {
		if mal, typ, pat := analyzePayload(value); mal {
			return true, typ + " in Multipart Metadata", pat
		}
	}

	content, err := io.ReadAll(io.LimitReader(part, maxMultipartPartBytes+1))
	if err != nil {
		return true, "MULTIPART_READ_ERROR", err.Error()
	}
	if len(content) > maxMultipartPartBytes {
		return true, "MULTIPART_PART_TOO_LARGE", "multipart part exceeds inspection limit"
	}
	if len(content) == 0 {
		return false, "", ""
	}

	if mal, typ, pat := analyzePayload(string(content)); mal {
		return true, typ + " in Multipart Body", pat
	}

	return false, "", ""
}
