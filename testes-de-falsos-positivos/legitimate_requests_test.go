package falsepositivetests

import (
	"net/http"
	"testing"
)

func TestLegitimateRequestsReachTheBackend(t *testing.T) {
	handler := newProtectedHandler(t)

	tests := []requestCase{
		{
			name:   "ordinary product search",
			method: http.MethodGet,
			target: "http://app.example/search?q=blue+cotton+shirt&size=medium",
		},
		{
			name:   "versioned static asset",
			method: http.MethodGet,
			target: "http://app.example/assets/app.min.js?v=20260802",
		},
		{
			name:        "normal profile update",
			method:      http.MethodPost,
			target:      "http://app.example/profile?tab=settings",
			body:        "name=Maria&note=regular+account+update",
			contentType: "application/x-www-form-urlencoded",
		},
		{
			name:        "JSON containing punctuation",
			method:      http.MethodPost,
			target:      "http://app.example/catalog",
			body:        `{"publisher":"O'Reilly Media","description":"Five is greater than three."}`,
			contentType: "application/json",
		},
		{
			name:        "public API destination",
			method:      http.MethodPost,
			target:      "http://app.example/integrations",
			body:        `{"endpoint":"https://api.example.com/v1/catalog"}`,
			contentType: "application/json",
		},
		{
			name:   "normal browser headers",
			method: http.MethodGet,
			target: "http://app.example/docs/security-guide",
			headers: map[string]string{
				"Accept-Language": "en-US,en;q=0.9",
				"User-Agent":      "Mozilla/5.0 DoBotWAF-Regression-Test",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := executeRequest(t, handler, test)
			if response.Code != http.StatusNoContent {
				t.Fatalf("expected backend status 204, got %d; body=%q", response.Code, response.Body.String())
			}
			if action := response.Header().Get("X-DoBotShield-Action"); action != "Forwarded" {
				t.Fatalf("expected Forwarded action, got %q", action)
			}
		})
	}
}
