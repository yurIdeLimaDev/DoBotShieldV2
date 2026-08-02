package falsepositivetests

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dobotshield/blocklist"
	"dobotshield/config"
	"dobotshield/middleware"
	"dobotshield/ratelimit"
)

type requestCase struct {
	name        string
	method      string
	target      string
	body        string
	contentType string
	headers     map[string]string
}

func newProtectedHandler(t *testing.T) http.Handler {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(backend.Close)

	cfg := config.Config{
		TargetURL:             backend.URL,
		EnableSanitizer:       true,
		WAFMode:               "block",
		MaxBodySize:           1 << 20,
		MaxDecodedBodySize:    4 << 20,
		MaxURLLength:          8192,
		MaxHeaderBytes:        64 << 10,
		MaxHeaderCount:        100,
		MaxConcurrentRequests: 32,
		EnableRateLimit:       false,
	}

	proxy, err := middleware.BuildProxy(cfg)
	if err != nil {
		t.Fatalf("build protected proxy: %v", err)
	}

	limiter := ratelimit.NewManager(128, 1000, 1000, 100)
	return middleware.MakeSecureHandler(proxy, limiter, blocklist.New(nil), cfg)
}

func executeRequest(t *testing.T, handler http.Handler, test requestCase) *httptest.ResponseRecorder {
	t.Helper()

	var body io.Reader
	if test.body != "" {
		body = strings.NewReader(test.body)
	}
	req := httptest.NewRequest(test.method, test.target, body)
	req.RemoteAddr = "203.0.113.25:49152"
	if test.contentType != "" {
		req.Header.Set("Content-Type", test.contentType)
	}
	for name, value := range test.headers {
		req.Header.Set(name, value)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}
