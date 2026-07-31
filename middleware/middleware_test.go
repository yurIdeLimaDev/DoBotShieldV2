package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"dobotshield/blocklist"
	"dobotshield/config"
	"dobotshield/ratelimit"
	"dobotshield/traininglog"
	"dobotshield/waf"
)

func TestInjectForwardedHeadersStripsUntrustedForwarding(t *testing.T) {
	r := httptest.NewRequest("GET", "https://dobotshield.local/", nil)
	r.RemoteAddr = "203.0.113.10:49152"
	r.Header.Set("Forwarded", "for=198.51.100.20")
	r.Header.Set("X-Forwarded-For", "198.51.100.20")

	injectForwardedHeaders(r, "203.0.113.10", "203.0.113.10", false)

	if got := r.Header.Get("Forwarded"); got != "" {
		t.Fatalf("expected Forwarded to be removed, got %q", got)
	}
	if got := r.Header.Get("X-Forwarded-For"); got != "203.0.113.10" {
		t.Fatalf("expected sanitized X-Forwarded-For, got %q", got)
	}
	if got := r.Header.Get("X-Real-IP"); got != "203.0.113.10" {
		t.Fatalf("expected X-Real-IP to use client IP, got %q", got)
	}
}

func TestInjectForwardedHeadersRebuildsTrustedProxyChain(t *testing.T) {
	r := httptest.NewRequest("GET", "https://dobotshield.local/", nil)
	r.RemoteAddr = "10.0.0.5:49152"
	r.Header.Set("X-Forwarded-For", "198.51.100.20, 10.0.0.4")

	injectForwardedHeaders(r, "198.51.100.20", "10.0.0.5", true)

	if got := r.Header.Get("X-Forwarded-For"); got != "198.51.100.20, 10.0.0.5" {
		t.Fatalf("expected rebuilt X-Forwarded-For, got %q", got)
	}
	if got := r.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("expected X-Forwarded-Proto=https, got %q", got)
	}
}

func TestInjectForwardedHeadersUsesIncomingScheme(t *testing.T) {
	for _, test := range []struct {
		name string
		url  string
		want string
	}{
		{name: "http", url: "http://dobotshield.local/", want: "http"},
		{name: "https", url: "https://dobotshield.local/", want: "https"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, test.url, nil)
			r.RemoteAddr = "203.0.113.10:49152"

			injectForwardedHeaders(r, "203.0.113.10", "203.0.113.10", false)

			if got := r.Header.Get("X-Forwarded-Proto"); got != test.want {
				t.Fatalf("expected X-Forwarded-Proto=%q, got %q", test.want, got)
			}
		})
	}
}

func TestSecureHandlerDoesNotDuplicateXForwardedForInReverseProxy(t *testing.T) {
	forwardedFor := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedFor <- r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	cfg := config.Config{
		TargetURL:       backend.URL,
		WAFMode:         "off",
		MaxBodySize:     1 << 20,
		EnableRateLimit: false,
	}
	proxy, err := BuildProxy(cfg)
	if err != nil {
		t.Fatalf("build proxy: %v", err)
	}
	handler := MakeSecureHandler(proxy, ratelimit.NewManager(100, 10, 20, 10), blocklist.New(nil), cfg)

	req := httptest.NewRequest(http.MethodGet, "http://dobotshield.local/health", nil)
	req.RemoteAddr = "203.0.113.10:49152"
	req.Header.Set("X-Forwarded-For", "198.51.100.20")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected backend status 204, got %d", rec.Code)
	}
	if got := <-forwardedFor; got != "203.0.113.10" {
		t.Fatalf("expected one sanitized X-Forwarded-For value, got %q", got)
	}
}

func TestWriteJSONErrorUsesGenericReason(t *testing.T) {
	w := httptest.NewRecorder()

	writeJSONError(w, http.StatusBadRequest, "Security Violation", "Request blocked by security policy")

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected JSON response: %v", err)
	}
	if body["reason"] != "Request blocked by security policy" {
		t.Fatalf("expected generic reason, got %q", body["reason"])
	}
}

func TestBlockedMethods(t *testing.T) {
	if !isBlockedMethod(http.MethodTrace) {
		t.Fatalf("expected TRACE to be blocked")
	}
	if !isBlockedMethod("TRACK") {
		t.Fatalf("expected TRACK to be blocked")
	}
	if isBlockedMethod(http.MethodGet) {
		t.Fatalf("expected GET to be allowed")
	}
}

func TestBuildProxyDoesNotSetCSPByDefault(t *testing.T) {
	proxy, err := BuildProxy(config.Config{TargetURL: "http://localhost:4280"})
	if err != nil {
		t.Fatalf("unexpected proxy error: %v", err)
	}

	resp := &http.Response{Header: make(http.Header)}
	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected modify response error: %v", err)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != "" {
		t.Fatalf("expected CSP to be omitted by default, got %q", got)
	}
}

func TestBuildProxySetsConfiguredCSP(t *testing.T) {
	proxy, err := BuildProxy(config.Config{
		TargetURL:             "http://localhost:4280",
		ContentSecurityPolicy: "default-src 'self'",
	})
	if err != nil {
		t.Fatalf("unexpected proxy error: %v", err)
	}

	resp := &http.Response{Header: make(http.Header)}
	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected modify response error: %v", err)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != "default-src 'self'" {
		t.Fatalf("expected configured CSP, got %q", got)
	}
}

func TestBuildProxyBlocksBackendSQLLeak(t *testing.T) {
	proxy, err := BuildProxy(config.Config{
		TargetURL:                     "http://localhost:4280",
		EnableSanitizer:               true,
		WAFMode:                       "block",
		EnableResponseInspection:      true,
		ResponseInspectionLimit:       1024,
		ResponseDiagnosticsErrorsOnly: true,
	})
	if err != nil {
		t.Fatalf("unexpected proxy error: %v", err)
	}

	req := httptest.NewRequest("GET", "https://dobotshield.local/items", nil)
	req.Header.Set("X-Request-ID", "test-request")
	req.Header.Set("X-Real-IP", "203.0.113.10")
	resp := &http.Response{
		StatusCode:    http.StatusInternalServerError,
		Status:        "500 Internal Server Error",
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewBufferString("SQLSTATE[42000]: syntax error near 'DROP'")),
		ContentLength: int64(len("SQLSTATE[42000]: syntax error near 'DROP'")),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/plain")

	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected modify response error: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected blocked response status 502, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-DoBotShield-Action"); got != "Blocked-Response-WAF" {
		t.Fatalf("expected blocked response action, got %q", got)
	}
}

func TestBuildProxyMonitorModeDoesNotBlockBackendLeak(t *testing.T) {
	proxy, err := BuildProxy(config.Config{
		TargetURL:                "http://localhost:4280",
		EnableSanitizer:          true,
		WAFMode:                  "monitor",
		EnableResponseInspection: true,
		ResponseInspectionLimit:  1024,
	})
	if err != nil {
		t.Fatalf("unexpected proxy error: %v", err)
	}

	req := httptest.NewRequest("GET", "https://dobotshield.local/items", nil)
	req.Header.Set("X-Request-ID", "test-request")
	resp := &http.Response{
		StatusCode:    http.StatusInternalServerError,
		Status:        "500 Internal Server Error",
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewBufferString("SQLSTATE[42000]: syntax error near 'DROP'")),
		ContentLength: int64(len("SQLSTATE[42000]: syntax error near 'DROP'")),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/plain")

	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected modify response error: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected monitor mode to keep backend status, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-DoBotShield-Action"); got != "Forwarded" {
		t.Fatalf("expected forwarded action in monitor mode, got %q", got)
	}
}

func TestCustomResponseHeaderBlockDoesNotRelayBackendHeaders(t *testing.T) {
	rules, err := waf.CompileCustomRules(waf.CustomRulesFile{
		Version: 1,
		Rules:   []waf.CustomRuleConfig{{ID: "internal", Phase: "response", Target: "headers", Pattern: `INTERNAL-[0-9]+`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := BuildProxyWithRules(config.Config{
		TargetURL:                "http://localhost:4280",
		EnableSanitizer:          true,
		WAFMode:                  "block",
		EnableResponseInspection: true,
		ResponseInspectionLimit:  1024,
	}, rules)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://dobotshield.local/private", nil)
	req.Header.Set("X-Request-ID", "test-request")
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("ordinary body")),
		ContentLength: int64(len("ordinary body")),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/plain")
	resp.Header.Set("X-Internal-Marker", "INTERNAL-778899")
	resp.Header.Set("Set-Cookie", "session=secret")

	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected blocked response, got %d", resp.StatusCode)
	}
	for _, name := range []string{"X-Internal-Marker", "Set-Cookie"} {
		if value := resp.Header.Get(name); value != "" {
			t.Fatalf("blocked response leaked %s: %q", name, value)
		}
	}
	if resp.Header.Get("X-Request-ID") != "test-request" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("expected local correlation and security headers, got %v", resp.Header)
	}
}

func TestSecureHandlerRecordsTrainingEventOnBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "training.jsonl")
	traininglog.Configure(true, path)
	t.Cleanup(func() { _ = traininglog.CloseDefault() })

	cfg := config.Config{
		TargetURL:       "http://127.0.0.1:9",
		EnableSanitizer: true,
		WAFMode:         "block",
		MaxBodySize:     1 << 20,
		EnableRateLimit: false,
	}

	proxy, err := BuildProxy(cfg)
	if err != nil {
		t.Fatalf("build proxy: %v", err)
	}
	fw := ratelimit.NewManager(100, 10, 20, 10)
	bl := blocklist.New(nil)

	handler := MakeSecureHandler(proxy, fw, bl, cfg)

	req := httptest.NewRequest("GET", "https://dobotshield.local/search?q=<script>alert(1)</script>", nil)
	req.RemoteAddr = "203.0.113.50:12345"
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected blocked request to return 400, got %d", rec.Code)
	}

	_ = traininglog.CloseDefault()

	events, err := traininglog.Load(path)
	if err != nil {
		t.Fatalf("load training log: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected exactly one training event, got %d", len(events))
	}

	ev := events[0]
	if ev.Category != "XSS" {
		t.Fatalf("expected category XSS, got %q", ev.Category)
	}
	if ev.Phase != "request" || ev.Action != "blocked" {
		t.Fatalf("expected request/blocked, got %s/%s", ev.Phase, ev.Action)
	}
	if ev.IP != "203.0.113.50" {
		t.Fatalf("expected client IP recorded, got %q", ev.IP)
	}
	if ev.Rule == "" {
		t.Fatalf("expected the specific rule (regex) to be recorded")
	}
	if ev.Timestamp == "" {
		t.Fatalf("expected a timestamp")
	}
	if len(ev.Variants) == 0 {
		t.Fatalf("expected generated variants to be recorded")
	}
}

func TestSecureHandlerNoTrainingEventWhenDisabled(t *testing.T) {
	traininglog.Configure(false, "")
	t.Cleanup(func() { _ = traininglog.CloseDefault() })

	cfg := config.Config{
		TargetURL:       "http://127.0.0.1:9",
		EnableSanitizer: true,
		WAFMode:         "block",
		MaxBodySize:     1 << 20,
		EnableRateLimit: false,
	}
	proxy, err := BuildProxy(cfg)
	if err != nil {
		t.Fatalf("build proxy: %v", err)
	}
	handler := MakeSecureHandler(proxy, ratelimit.NewManager(100, 10, 20, 10), blocklist.New(nil), cfg)

	req := httptest.NewRequest("GET", "https://dobotshield.local/search?q=<script>alert(1)</script>", nil)
	req.RemoteAddr = "203.0.113.51:12345"
	rec := httptest.NewRecorder()

	handler(rec, req) // must not panic when training logging is disabled

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected blocked request to return 400, got %d", rec.Code)
	}
	if traininglog.Enabled() {
		t.Fatalf("expected training logging to be disabled")
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	r := httptest.NewRequest("GET", "https://dobotshield.local/ws", nil)
	r.Header.Set("Connection", "keep-alive, Upgrade")
	r.Header.Set("Upgrade", "websocket")

	if !isWebSocketUpgrade(r) {
		t.Fatalf("expected websocket upgrade to be detected")
	}
}

func TestBuildProxyUsesUpstreamHostByDefault(t *testing.T) {
	receivedHost := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost <- r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	cfg := config.Config{TargetURL: backend.URL, WAFMode: "off", MaxBodySize: 1024}
	proxy, err := BuildProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := MakeSecureHandler(proxy, ratelimit.NewManager(100, 10, 20, 10), blocklist.New(nil), cfg)
	req := httptest.NewRequest(http.MethodGet, "http://public.example/", nil)
	req.RemoteAddr = "203.0.113.20:40000"
	recorder := httptest.NewRecorder()
	handler(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected backend response, got %d", recorder.Code)
	}
	backendURL := strings.TrimPrefix(backend.URL, "http://")
	if got := <-receivedHost; got != backendURL {
		t.Fatalf("expected upstream host %q, got %q", backendURL, got)
	}
}

func TestBuildProxyRejectsNonHTTPUpstream(t *testing.T) {
	if _, err := BuildProxy(config.Config{TargetURL: "file:///etc/passwd"}); err == nil {
		t.Fatal("expected non-HTTP upstream to be rejected")
	}
}

func TestResponseInspectionAllowsSuccessfulDocumentationByDefault(t *testing.T) {
	proxy, err := BuildProxy(config.Config{
		TargetURL:                     "http://localhost:4280",
		EnableSanitizer:               true,
		WAFMode:                       "block",
		EnableResponseInspection:      true,
		ResponseInspectionLimit:       1024,
		ResponseDiagnosticsErrorsOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://dobotshield.local/instructions", nil)
	body := "SQLSTATE[42000] documentation and <script>alert(1)</script>"
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/html")

	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected documentation response to pass, got %d", resp.StatusCode)
	}
}

func TestResponseInspectionScansOversizedPrefix(t *testing.T) {
	proxy, err := BuildProxy(config.Config{
		TargetURL:                "http://localhost:4280",
		EnableSanitizer:          true,
		WAFMode:                  "block",
		EnableResponseInspection: true,
		ResponseInspectionLimit:  64,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://dobotshield.local/error", nil)
	body := "SQLSTATE[42000]: syntax error " + strings.Repeat("A", 256)
	resp := &http.Response{
		StatusCode:    http.StatusInternalServerError,
		Status:        "500 Internal Server Error",
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/plain")

	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected malicious prefix to be blocked, got %d", resp.StatusCode)
	}
}

func TestHardenCookiesIsExplicitAndSchemeAware(t *testing.T) {
	header := make(http.Header)
	header.Add("Set-Cookie", "session=abc; Path=/")
	hardenSetCookies(header, true)
	value := header.Get("Set-Cookie")
	for _, attribute := range []string{"HttpOnly", "SameSite=Lax", "Secure"} {
		if !strings.Contains(value, attribute) {
			t.Fatalf("expected %s in hardened cookie %q", attribute, value)
		}
	}
}

func TestHardenCookiesDoesNotMistakeAttributePrefixes(t *testing.T) {
	header := make(http.Header)
	header.Add("Set-Cookie", "session=abc; SecureFlag=yes; HttpOnlyFlag=yes; SameSiteFlag=Lax")

	hardenSetCookies(header, true)
	value := header.Get("Set-Cookie")
	for _, attribute := range []string{"; HttpOnly", "; SameSite=Lax", "; Secure"} {
		if !strings.Contains(value, attribute) {
			t.Fatalf("expected exact %s attribute in hardened cookie %q", attribute, value)
		}
	}
}

func TestClearLocalResponseHeadersPreventsProxyDuplicates(t *testing.T) {
	header := make(http.Header)
	applyCommonSecurityHeaders(header, config.Config{ContentSecurityPolicy: "default-src 'self'"}, true)
	header.Set("X-Request-ID", "request-id")

	clearLocalResponseHeaders(header)
	for _, name := range []string{"Strict-Transport-Security", "X-Frame-Options", "Content-Security-Policy", "X-Request-ID"} {
		if values := header.Values(name); len(values) != 0 {
			t.Fatalf("expected %s to be cleared, got %v", name, values)
		}
	}
}
