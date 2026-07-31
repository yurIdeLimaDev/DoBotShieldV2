package config

import "testing"

func TestLoadReadsEveryAdminConfigEnvironmentVariable(t *testing.T) {
	t.Setenv("TARGET_URL", "https://backend.example:9443")
	t.Setenv("PROXY_PORT", "127.0.0.1:8443")
	t.Setenv("HTTP_MODE", "true")
	t.Setenv("ENABLE_WAF", "true")
	t.Setenv("WAF_MODE", "monitor")
	t.Setenv("ENABLE_RESPONSE_INSPECTION", "false")
	t.Setenv("ENABLE_RATE_LIMIT", "false")
	t.Setenv("RATE_LIMIT", "12.5")
	t.Setenv("BURST_LIMIT", "25")
	t.Setenv("MAX_CONNS", "15")
	t.Setenv("MAX_TRACKED_IPS", "750")
	t.Setenv("MAX_CONCURRENT_REQUESTS", "1200")
	t.Setenv("MAX_BODY_SIZE", "2097152")
	t.Setenv("MAX_DECODED_BODY_SIZE", "8388608")
	t.Setenv("MAX_URL_LENGTH", "4096")
	t.Setenv("MAX_HEADER_BYTES", "32768")
	t.Setenv("MAX_HEADER_COUNT", "80")
	t.Setenv("RESPONSE_INSPECTION_LIMIT", "524288")
	t.Setenv("ENABLE_RESPONSE_XSS", "true")
	t.Setenv("RESPONSE_DIAGNOSTICS_ERRORS_ONLY", "false")
	t.Setenv("CERT_FILE", "tls/cert.pem")
	t.Setenv("KEY_FILE", "tls/key.pem")
	t.Setenv("TRUSTED_PROXIES", "192.0.2.10,2001:db8::1")
	t.Setenv("INSECURE_SKIP_VERIFY", "true")
	t.Setenv("CONTENT_SECURITY_POLICY", "default-src 'self'")
	t.Setenv("WAF_ALLOWLIST", "SQLi:/search")
	t.Setenv("ALLOWED_HOSTS", "app.example.com,*.example.net")
	t.Setenv("ALLOWED_METHODS", "GET,POST")
	t.Setenv("PRESERVE_HOST", "true")
	t.Setenv("HARDEN_COOKIES", "true")
	t.Setenv("BLOCKED_IPS", "198.51.100.10,203.0.113.0/24")
	t.Setenv("RATE_LIMIT_STATE_FILE", "state/rate.json")
	t.Setenv("TRAINING_MODE", "false")
	t.Setenv("TRAINING_LOG_FILE", "audit/events.jsonl")
	t.Setenv("TRAINING_REDACT_SENSITIVE", "false")
	t.Setenv("CUSTOM_RULES_FILE", "policy/custom-rules.json")
	t.Setenv("ENABLE_WEBSOCKET_PROTECTION", "true")
	t.Setenv("WEBSOCKET_ALLOWED_ORIGINS", "https://app.example.com,*.trusted.example")
	t.Setenv("WEBSOCKET_MAX_MESSAGE_SIZE", "2097152")
	t.Setenv("WEBSOCKET_MESSAGES_PER_SECOND", "75.5")
	t.Setenv("WEBSOCKET_BURST_LIMIT", "150")
	t.Setenv("WEBSOCKET_INSPECT_BINARY", "true")

	cfg := Load()
	if cfg.TargetURL != "https://backend.example:9443" || cfg.ProxyPort != "127.0.0.1:8443" || !cfg.HTTPMode {
		t.Fatalf("target/proxy not loaded: %+v", cfg)
	}
	if !cfg.EnableSanitizer || cfg.WAFMode != "monitor" || cfg.EnableResponseInspection || cfg.EnableRateLimit {
		t.Fatalf("WAF toggles not loaded: %+v", cfg)
	}
	if cfg.RateLimit != 12.5 || cfg.BurstLimit != 25 || cfg.MaxConnsPerIP != 15 || cfg.MaxTrackedIPs != 750 || cfg.MaxConcurrentRequests != 1200 {
		t.Fatalf("limits not loaded: %+v", cfg)
	}
	if cfg.MaxBodySize != 2097152 || cfg.MaxDecodedBodySize != 8388608 || cfg.ResponseInspectionLimit != 524288 {
		t.Fatalf("inspection sizes not loaded: %+v", cfg)
	}
	if cfg.MaxURLLength != 4096 || cfg.MaxHeaderBytes != 32768 || cfg.MaxHeaderCount != 80 {
		t.Fatalf("protocol limits not loaded: %+v", cfg)
	}
	if !cfg.EnableResponseXSS || cfg.ResponseDiagnosticsErrorsOnly {
		t.Fatalf("response policy not loaded: %+v", cfg)
	}
	if cfg.CertFile != "tls/cert.pem" || cfg.KeyFile != "tls/key.pem" || !cfg.InsecureSkipVerify {
		t.Fatalf("TLS options not loaded: %+v", cfg)
	}
	if len(cfg.TrustedProxies) != 2 || cfg.TrustedProxies[1] != "2001:db8::1" {
		t.Fatalf("trusted proxies not loaded: %#v", cfg.TrustedProxies)
	}
	if cfg.ContentSecurityPolicy != "default-src 'self'" || len(cfg.WAFAllowlist) != 1 {
		t.Fatalf("WAF policy options not loaded: %+v", cfg)
	}
	if len(cfg.AllowedHosts) != 2 || len(cfg.AllowedMethods) != 2 || !cfg.PreserveHost || !cfg.HardenCookies {
		t.Fatalf("request routing policy not loaded: %+v", cfg)
	}
	if len(cfg.BlockedIPs) != 2 || cfg.BlockedIPs[1] != "203.0.113.0/24" {
		t.Fatalf("blocked IPs not loaded: %#v", cfg.BlockedIPs)
	}
	if cfg.RateLimitStateFile != "state/rate.json" || cfg.TrainingMode || cfg.TrainingLogFile != "audit/events.jsonl" || cfg.TrainingRedactSensitive {
		t.Fatalf("state/training options not loaded: %+v", cfg)
	}
	if cfg.CustomRulesFile != "policy/custom-rules.json" || !cfg.EnableWebSocketProtection || len(cfg.WebSocketAllowedOrigins) != 2 {
		t.Fatalf("custom/WebSocket options not loaded: %+v", cfg)
	}
	if cfg.WebSocketMaxMessageSize != 2097152 || cfg.WebSocketMessagesPerSecond != 75.5 || cfg.WebSocketBurstLimit != 150 || !cfg.WebSocketInspectBinary {
		t.Fatalf("WebSocket limits not loaded: %+v", cfg)
	}
}

func TestLoadReadsSecurityTogglesFromEnv(t *testing.T) {
	t.Setenv("ENABLE_WAF", "false")
	t.Setenv("ENABLE_RATE_LIMIT", "off")
	t.Setenv("MAX_BODY_SIZE", "2097152")
	t.Setenv("CONTENT_SECURITY_POLICY", "default-src 'self'")
	t.Setenv("INSECURE_SKIP_VERIFY", "true")
	t.Setenv("WAF_MODE", "monitor")
	t.Setenv("ENABLE_RESPONSE_INSPECTION", "false")
	t.Setenv("RESPONSE_INSPECTION_LIMIT", "524288")
	t.Setenv("MAX_TRACKED_IPS", "500")
	t.Setenv("WAF_ALLOWLIST", "SQLi:/api/search,XSS:/content-editor,/health")
	t.Setenv("RATE_LIMIT_STATE_FILE", "state/ratelimit.json")

	cfg := Load()

	if cfg.EnableSanitizer {
		t.Fatalf("expected ENABLE_WAF=false to disable sanitizer")
	}
	if cfg.EnableRateLimit {
		t.Fatalf("expected ENABLE_RATE_LIMIT=off to disable rate limit")
	}
	if cfg.MaxBodySize != 2097152 {
		t.Fatalf("expected MAX_BODY_SIZE to be read, got %d", cfg.MaxBodySize)
	}
	if cfg.ContentSecurityPolicy != "default-src 'self'" {
		t.Fatalf("expected CONTENT_SECURITY_POLICY to be read")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatalf("expected INSECURE_SKIP_VERIFY=true to be read")
	}
	if cfg.WAFMode != "monitor" {
		t.Fatalf("expected WAF_MODE=monitor, got %q", cfg.WAFMode)
	}
	if cfg.EnableResponseInspection {
		t.Fatalf("expected ENABLE_RESPONSE_INSPECTION=false to be read")
	}
	if cfg.ResponseInspectionLimit != 524288 {
		t.Fatalf("expected RESPONSE_INSPECTION_LIMIT to be read, got %d", cfg.ResponseInspectionLimit)
	}
	if cfg.MaxTrackedIPs != 500 {
		t.Fatalf("expected MAX_TRACKED_IPS to be read, got %d", cfg.MaxTrackedIPs)
	}
	if cfg.RateLimitStateFile != "state/ratelimit.json" {
		t.Fatalf("expected RATE_LIMIT_STATE_FILE to be read")
	}
	if !IsWAFAllowed(cfg.WAFAllowlist, "SQLi in Query", "/api/search") {
		t.Fatalf("expected SQLi allowlist rule to match /api/search")
	}
	if !IsWAFAllowed(cfg.WAFAllowlist, "XSS in Body", "/content-editor/post") {
		t.Fatalf("expected XSS allowlist rule to match /content-editor/post")
	}
	if !IsWAFAllowed(cfg.WAFAllowlist, "CMD_INJ in Query", "/health") {
		t.Fatalf("expected catch-all allowlist rule to match /health")
	}
	if IsWAFAllowed(cfg.WAFAllowlist, "XSS in Query", "/api/search") {
		t.Fatalf("did not expect XSS to match SQLi-only allowlist rule")
	}
}

func TestLoadUsesSecureTrainingDefaults(t *testing.T) {
	cfg := Load()

	if cfg.TrainingMode {
		t.Fatalf("expected TRAINING_MODE to default to false")
	}
	if cfg.TrainingLogFile != "logs/training.jsonl" {
		t.Fatalf("expected default training log file, got %q", cfg.TrainingLogFile)
	}
	if cfg.TrainingEnabled() {
		t.Fatalf("expected training to be disabled by default")
	}
	if !cfg.TrainingRedactSensitive {
		t.Fatalf("expected sensitive training fields to be redacted by default")
	}
}

func TestLoadUsesSecureWebSocketDefaults(t *testing.T) {
	cfg := Load()
	if !cfg.EnableWebSocketProtection {
		t.Fatal("expected WebSocket message protection to be enabled by default")
	}
	if len(cfg.WebSocketAllowedOrigins) != 0 {
		t.Fatalf("expected same-origin policy by default, got %#v", cfg.WebSocketAllowedOrigins)
	}
	if cfg.WebSocketMaxMessageSize != 1024*1024 || cfg.WebSocketMessagesPerSecond != 50 || cfg.WebSocketBurstLimit != 100 {
		t.Fatalf("unexpected WebSocket defaults: %+v", cfg)
	}
	if cfg.WebSocketInspectBinary {
		t.Fatal("expected binary message inspection to require explicit opt-in")
	}
}

func TestValidateRejectsUnsafeWebSocketConfiguration(t *testing.T) {
	base := Config{
		TargetURL:                  "http://backend.example",
		ProxyPort:                  ":8443",
		AllowedMethods:             []string{"GET"},
		EnableWebSocketProtection:  true,
		WebSocketMaxMessageSize:    1024,
		WebSocketMessagesPerSecond: 10,
		WebSocketBurstLimit:        10,
		WebSocketAllowedOrigins:    []string{"https://app.example"},
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "message too small", mutate: func(cfg *Config) { cfg.WebSocketMaxMessageSize = 1 }},
		{name: "message too large", mutate: func(cfg *Config) { cfg.WebSocketMaxMessageSize = 17 * 1024 * 1024 }},
		{name: "zero rate", mutate: func(cfg *Config) { cfg.WebSocketMessagesPerSecond = 0 }},
		{name: "zero burst", mutate: func(cfg *Config) { cfg.WebSocketBurstLimit = 0 }},
		{name: "wildcard origin", mutate: func(cfg *Config) { cfg.WebSocketAllowedOrigins = []string{"*"} }},
		{name: "origin path", mutate: func(cfg *Config) { cfg.WebSocketAllowedOrigins = []string{"https://app.example/path"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := base
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected invalid WebSocket configuration to be rejected")
			}
		})
	}
}

func TestLoadReadsTrainingOverrides(t *testing.T) {
	t.Setenv("TRAINING_MODE", "false")
	t.Setenv("TRAINING_LOG_FILE", "data/attacks.jsonl")

	cfg := Load()

	if cfg.TrainingMode {
		t.Fatalf("expected TRAINING_MODE=false to disable training mode")
	}
	if cfg.TrainingLogFile != "data/attacks.jsonl" {
		t.Fatalf("expected TRAINING_LOG_FILE override, got %q", cfg.TrainingLogFile)
	}
	if cfg.TrainingEnabled() {
		t.Fatalf("expected training disabled when TrainingMode is false")
	}
}

func TestLoadFallsBackForInvalidNumbers(t *testing.T) {
	t.Setenv("RATE_LIMIT", "0")
	t.Setenv("BURST_LIMIT", "-1")
	t.Setenv("MAX_CONNS", "not-a-number")
	t.Setenv("MAX_BODY_SIZE", "-100")

	cfg := Load()

	if cfg.RateLimit != 10.0 {
		t.Fatalf("expected default rate limit, got %f", cfg.RateLimit)
	}
	if cfg.BurstLimit != 20 {
		t.Fatalf("expected default burst limit, got %d", cfg.BurstLimit)
	}
	if cfg.MaxConnsPerIP != 10 {
		t.Fatalf("expected default max connections, got %d", cfg.MaxConnsPerIP)
	}
	if cfg.MaxBodySize != 1024*1024 {
		t.Fatalf("expected default body size, got %d", cfg.MaxBodySize)
	}
}

func TestResponseInspectionRequiresWAFAndResponseToggle(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{name: "enabled", cfg: Config{EnableSanitizer: true, EnableResponseInspection: true, WAFMode: "block"}, want: true},
		{name: "waf disabled", cfg: Config{EnableSanitizer: false, EnableResponseInspection: true, WAFMode: "block"}, want: false},
		{name: "response disabled", cfg: Config{EnableSanitizer: true, EnableResponseInspection: false, WAFMode: "block"}, want: false},
		{name: "mode off", cfg: Config{EnableSanitizer: true, EnableResponseInspection: true, WAFMode: "off"}, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.cfg.ResponseWAFEnabled(); got != test.want {
				t.Fatalf("ResponseWAFEnabled() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestWAFAllowlistUsesPathSegmentBoundaries(t *testing.T) {
	rules := []WAFAllowRule{{Category: "SQLI", PathPrefix: "/api"}}
	if !IsWAFAllowed(rules, "SQLi in Query", "/api/search") {
		t.Fatal("expected child path to match")
	}
	if IsWAFAllowed(rules, "SQLi in Query", "/api-admin") {
		t.Fatal("did not expect a lookalike prefix to bypass the WAF")
	}
}

func TestHostAllowlistSupportsExactAndWildcardHosts(t *testing.T) {
	cfg := Config{AllowedHosts: []string{"app.example.com", "*.service.example"}}
	for _, host := range []string{"app.example.com:443", "api.service.example"} {
		if !cfg.HostAllowed(host) {
			t.Fatalf("expected host %q to be allowed", host)
		}
	}
	for _, host := range []string{"example.com", "service.example", "evilservice.example"} {
		if cfg.HostAllowed(host) {
			t.Fatalf("expected host %q to be denied", host)
		}
	}
}

func TestValidateRejectsUnsafeTargetURL(t *testing.T) {
	cfg := Load()
	cfg.TargetURL = "file:///etc/passwd"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected non-HTTP target URL to be rejected")
	}
	cfg.TargetURL = "https://user:password@example.com/"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected embedded target credentials to be rejected")
	}
}
