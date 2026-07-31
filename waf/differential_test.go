package waf

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestDifferentialAgainstOWASPCRS is activated by the security workflow. It
// keeps a compact, high-confidence corpus aligned between DoBot Shield and the
// official OWASP CRS 4.25 LTS container without shipping a generated lab or
// bulky validation output in the repository.
func TestDifferentialAgainstOWASPCRS(t *testing.T) {
	crsURL := strings.TrimRight(strings.TrimSpace(os.Getenv("CRS_URL")), "/")
	if crsURL == "" {
		t.Skip("CRS_URL is set by the differential security workflow")
	}

	type differentialCase struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
		blocked     bool
	}
	tests := []differentialCase{
		{name: "benign home", method: http.MethodGet, path: "/", blocked: false},
		{name: "benign search", method: http.MethodGet, path: "/?q=blue+robot", blocked: false},
		{name: "benign JSON", method: http.MethodPost, path: "/api", body: `{"name":"Ada","role":"engineer"}`, contentType: "application/json", blocked: false},
		{name: "SQL injection", method: http.MethodGet, path: "/?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", blocked: true},
		{name: "cross-site scripting", method: http.MethodGet, path: "/?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", blocked: true},
		{name: "command injection", method: http.MethodGet, path: "/?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd", blocked: true},
		{name: "local file inclusion", method: http.MethodGet, path: "/?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd", blocked: true},
	}

	client := &http.Client{Timeout: 10 * time.Second}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			localBlocked, err := localDifferentialDecision(test.method, test.path, test.body, test.contentType)
			if err != nil {
				t.Fatal(err)
			}
			crsBlocked, status, err := crsDifferentialDecision(client, crsURL, test.method, test.path, test.body, test.contentType)
			if err != nil {
				t.Fatal(err)
			}
			if localBlocked != test.blocked {
				t.Fatalf("DoBot Shield blocked=%v, want %v", localBlocked, test.blocked)
			}
			if crsBlocked != test.blocked {
				t.Fatalf("OWASP CRS blocked=%v (HTTP %d), want %v", crsBlocked, status, test.blocked)
			}
			if localBlocked != crsBlocked {
				t.Fatalf("differential mismatch: DoBot Shield=%v OWASP CRS=%v", localBlocked, crsBlocked)
			}
		})
	}
}

func localDifferentialDecision(method, requestPath, body, contentType string) (bool, error) {
	parsed, err := url.Parse("http://example.test" + requestPath)
	if err != nil {
		return false, err
	}
	request := &http.Request{
		Method: method,
		Host:   "example.test",
		URL:    parsed,
		Header: make(http.Header),
		Body:   io.NopCloser(strings.NewReader(body)),
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	malicious, _, _ := CheckRequest(request, []byte(body))
	return malicious, nil
}

func crsDifferentialDecision(client *http.Client, baseURL, method, requestPath, body, contentType string) (bool, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, baseURL+requestPath, bytes.NewBufferString(body))
	if err != nil {
		return false, 0, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := client.Do(request)
	if err != nil {
		return false, 0, fmt.Errorf("request OWASP CRS: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return response.StatusCode == http.StatusForbidden, response.StatusCode, nil
}
