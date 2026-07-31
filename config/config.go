package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	TargetURL                     string
	ProxyPort                     string
	HTTPMode                      bool
	RateLimit                     float64
	BurstLimit                    int
	MaxConnsPerIP                 int
	EnableSanitizer               bool
	EnableRateLimit               bool
	CertFile                      string
	KeyFile                       string
	MaxBodySize                   int64
	TrustedProxies                []string
	BlockedIPs                    []string
	MaxTrackedIPs                 int
	MaxConcurrentRequests         int
	InsecureSkipVerify            bool
	ContentSecurityPolicy         string
	WAFMode                       string
	EnableResponseInspection      bool
	ResponseInspectionLimit       int64
	EnableResponseXSS             bool
	ResponseDiagnosticsErrorsOnly bool
	WAFAllowlist                  []WAFAllowRule
	AllowedHosts                  []string
	AllowedMethods                []string
	MaxURLLength                  int
	MaxHeaderBytes                int
	MaxHeaderCount                int
	MaxDecodedBodySize            int64
	PreserveHost                  bool
	HardenCookies                 bool
	RateLimitStateFile            string
	TrainingMode                  bool
	TrainingLogFile               string
	TrainingRedactSensitive       bool
	CustomRulesFile               string
	EnableWebSocketProtection     bool
	WebSocketAllowedOrigins       []string
	WebSocketMaxMessageSize       int64
	WebSocketMessagesPerSecond    float64
	WebSocketBurstLimit           int
	WebSocketInspectBinary        bool
}

type WAFAllowRule struct {
	Category   string
	PathPrefix string
}

func Load() Config {
	return Config{
		TargetURL:                     getEnv("TARGET_URL", "http://localhost:4280"),
		ProxyPort:                     getEnv("PROXY_PORT", ":443"),
		HTTPMode:                      parseBool(getEnv("HTTP_MODE", "false"), false),
		RateLimit:                     parseFloat(getEnv("RATE_LIMIT", "10.0"), 10.0),
		BurstLimit:                    parseInt(getEnv("BURST_LIMIT", "20"), 20),
		MaxConnsPerIP:                 parseInt(getEnv("MAX_CONNS", "10"), 10),
		EnableSanitizer:               parseBool(getEnv("ENABLE_WAF", "true"), true),
		EnableRateLimit:               parseBool(getEnv("ENABLE_RATE_LIMIT", "true"), true),
		CertFile:                      getEnv("CERT_FILE", "server.crt"),
		KeyFile:                       getEnv("KEY_FILE", "server.key"),
		MaxBodySize:                   parseInt64(getEnv("MAX_BODY_SIZE", "1048576"), 1024*1024),
		TrustedProxies:                parseCSV(getEnv("TRUSTED_PROXIES", "127.0.0.1,::1")),
		BlockedIPs:                    parseCSV(getEnv("BLOCKED_IPS", "")),
		MaxTrackedIPs:                 parseInt(getEnv("MAX_TRACKED_IPS", "10000"), 10000),
		MaxConcurrentRequests:         parseInt(getEnv("MAX_CONCURRENT_REQUESTS", "1000"), 1000),
		InsecureSkipVerify:            parseBool(getEnv("INSECURE_SKIP_VERIFY", "false"), false),
		ContentSecurityPolicy:         strings.TrimSpace(getEnv("CONTENT_SECURITY_POLICY", "")),
		WAFMode:                       parseWAFMode(getEnv("WAF_MODE", "block")),
		EnableResponseInspection:      parseBool(getEnv("ENABLE_RESPONSE_INSPECTION", "true"), true),
		ResponseInspectionLimit:       parseInt64(getEnv("RESPONSE_INSPECTION_LIMIT", "1048576"), 1024*1024),
		EnableResponseXSS:             parseBool(getEnv("ENABLE_RESPONSE_XSS", "false"), false),
		ResponseDiagnosticsErrorsOnly: parseBool(getEnv("RESPONSE_DIAGNOSTICS_ERRORS_ONLY", "true"), true),
		WAFAllowlist:                  parseWAFAllowlist(getEnv("WAF_ALLOWLIST", "")),
		AllowedHosts:                  parseCSV(getEnv("ALLOWED_HOSTS", "")),
		AllowedMethods:                parseMethods(getEnv("ALLOWED_METHODS", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS")),
		MaxURLLength:                  parseInt(getEnv("MAX_URL_LENGTH", "8192"), 8192),
		MaxHeaderBytes:                parseInt(getEnv("MAX_HEADER_BYTES", "65536"), 64*1024),
		MaxHeaderCount:                parseInt(getEnv("MAX_HEADER_COUNT", "100"), 100),
		MaxDecodedBodySize:            parseInt64(getEnv("MAX_DECODED_BODY_SIZE", "4194304"), 4*1024*1024),
		PreserveHost:                  parseBool(getEnv("PRESERVE_HOST", "false"), false),
		HardenCookies:                 parseBool(getEnv("HARDEN_COOKIES", "false"), false),
		RateLimitStateFile:            strings.TrimSpace(getEnv("RATE_LIMIT_STATE_FILE", "")),
		TrainingMode:                  parseBool(getEnv("TRAINING_MODE", "false"), false),
		TrainingLogFile:               strings.TrimSpace(getEnv("TRAINING_LOG_FILE", "logs/training.jsonl")),
		TrainingRedactSensitive:       parseBool(getEnv("TRAINING_REDACT_SENSITIVE", "true"), true),
		CustomRulesFile:               strings.TrimSpace(getEnv("CUSTOM_RULES_FILE", "")),
		EnableWebSocketProtection:     parseBool(getEnv("ENABLE_WEBSOCKET_PROTECTION", "true"), true),
		WebSocketAllowedOrigins:       parseCSV(getEnv("WEBSOCKET_ALLOWED_ORIGINS", "")),
		WebSocketMaxMessageSize:       parseInt64(getEnv("WEBSOCKET_MAX_MESSAGE_SIZE", "1048576"), 1024*1024),
		WebSocketMessagesPerSecond:    parseFloat(getEnv("WEBSOCKET_MESSAGES_PER_SECOND", "50"), 50),
		WebSocketBurstLimit:           parseInt(getEnv("WEBSOCKET_BURST_LIMIT", "100"), 100),
		WebSocketInspectBinary:        parseBool(getEnv("WEBSOCKET_INSPECT_BINARY", "false"), false),
	}
}

// Validate rejects security-sensitive configuration errors instead of silently
// starting with an ambiguous or unsafe proxy setup.
func (c Config) Validate() error {
	target, err := url.Parse(c.TargetURL)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return fmt.Errorf("TARGET_URL must be an absolute HTTP or HTTPS URL")
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return fmt.Errorf("TARGET_URL scheme must be http or https")
	}
	if target.User != nil || target.Fragment != "" {
		return fmt.Errorf("TARGET_URL must not contain credentials or a fragment")
	}
	if strings.ContainsAny(c.ContentSecurityPolicy, "\r\n") {
		return fmt.Errorf("CONTENT_SECURITY_POLICY must not contain line breaks")
	}
	if err := validateListenAddress(c.ProxyPort); err != nil {
		return err
	}
	if err := validateIPEntries("TRUSTED_PROXIES", c.TrustedProxies); err != nil {
		return err
	}
	if err := validateIPEntries("BLOCKED_IPS", c.BlockedIPs); err != nil {
		return err
	}
	if len(c.AllowedMethods) == 0 {
		return fmt.Errorf("ALLOWED_METHODS must contain at least one method")
	}
	for _, method := range c.AllowedMethods {
		if !validHTTPToken(method) {
			return fmt.Errorf("ALLOWED_METHODS contains an invalid method: %q", method)
		}
		if method == "TRACE" || method == "TRACK" {
			return fmt.Errorf("ALLOWED_METHODS must not enable %s", method)
		}
	}
	for _, host := range c.AllowedHosts {
		if !validAllowedHostPattern(host) {
			return fmt.Errorf("ALLOWED_HOSTS contains an invalid host pattern: %q", host)
		}
	}
	if c.EnableWebSocketProtection {
		if c.WebSocketMaxMessageSize < 1024 || c.WebSocketMaxMessageSize > 16*1024*1024 {
			return fmt.Errorf("WEBSOCKET_MAX_MESSAGE_SIZE must be between 1024 and 16777216 bytes")
		}
		if c.WebSocketMessagesPerSecond <= 0 || c.WebSocketMessagesPerSecond > 100000 {
			return fmt.Errorf("WEBSOCKET_MESSAGES_PER_SECOND must be greater than 0 and at most 100000")
		}
		if c.WebSocketBurstLimit < 1 || c.WebSocketBurstLimit > 100000 {
			return fmt.Errorf("WEBSOCKET_BURST_LIMIT must be between 1 and 100000")
		}
		for _, pattern := range c.WebSocketAllowedOrigins {
			if !validWebSocketOriginPattern(pattern) {
				return fmt.Errorf("WEBSOCKET_ALLOWED_ORIGINS contains an invalid or unsafe pattern: %q", pattern)
			}
		}
	}
	return nil
}

func validateListenAddress(address string) error {
	_, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return fmt.Errorf("PROXY_PORT must use :port, host:port, or [ipv6]:port syntax: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("PROXY_PORT must be between 1 and 65535")
	}
	return nil
}

func validateIPEntries(name string, entries []string) error {
	for _, entry := range entries {
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err == nil {
				continue
			}
		} else if net.ParseIP(entry) != nil {
			continue
		}
		return fmt.Errorf("%s contains an invalid IP address or CIDR: %q", name, entry)
	}
	return nil
}

// TrainingEnabled reports whether structured training-mode logging has both
// been explicitly enabled and given a destination file.
func (c Config) TrainingEnabled() bool {
	return c.TrainingMode && c.TrainingLogFile != ""
}

func (c Config) RequestWAFEnabled() bool {
	return c.EnableSanitizer && c.WAFMode != "off"
}

func (c Config) ResponseWAFEnabled() bool {
	return c.EnableSanitizer && c.EnableResponseInspection && c.WAFMode != "off"
}

func (c Config) WAFBlocks() bool {
	return c.WAFMode == "block"
}

func (c Config) MethodAllowed(method string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "TRACE" || method == "TRACK" {
		return false
	}
	allowedMethods := c.EffectiveAllowedMethods()
	for _, allowed := range allowedMethods {
		if method == allowed {
			return true
		}
	}
	return false
}

func (c Config) EffectiveAllowedMethods() []string {
	if len(c.AllowedMethods) > 0 {
		return c.AllowedMethods
	}
	return []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
}

func (c Config) HostAllowed(hostPort string) bool {
	if len(c.AllowedHosts) == 0 {
		return true
	}

	host := canonicalHost(hostPort)
	if host == "" {
		return false
	}
	for _, rawPattern := range c.AllowedHosts {
		pattern := canonicalHost(rawPattern)
		if pattern == "" {
			continue
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*")
			if strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".") {
				return true
			}
			continue
		}
		if host == pattern {
			return true
		}
	}
	return false
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func parseInt(s string, defaultVal int) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || v <= 0 {
		return defaultVal
	}
	return v
}

func parseFloat(s string, defaultVal float64) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v <= 0 {
		return defaultVal
	}
	return v
}

func parseInt64(s string, defaultVal int64) int64 {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || v <= 0 {
		return defaultVal
	}
	return v
}

func parseBool(s string, defaultVal bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "t", "yes", "y", "on", "enabled":
		return true
	case "0", "false", "f", "no", "n", "off", "disabled":
		return false
	default:
		return defaultVal
	}
}

func parseCSV(s string) []string {
	parts := strings.Split(s, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func parseMethods(s string) []string {
	values := parseCSV(s)
	methods := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		method := strings.ToUpper(value)
		if method == "" {
			continue
		}
		if _, exists := seen[method]; exists {
			continue
		}
		seen[method] = struct{}{}
		methods = append(methods, method)
	}
	return methods
}

func parseWAFMode(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "block", "enforce", "blocking":
		return "block"
	case "monitor", "observe", "dry-run", "dryrun", "detect", "detect-only":
		return "monitor"
	case "off", "disabled", "disable":
		return "off"
	default:
		return "block"
	}
}

func parseWAFAllowlist(s string) []WAFAllowRule {
	entries := parseCSV(s)
	rules := make([]WAFAllowRule, 0, len(entries))

	for _, entry := range entries {
		category := "*"
		pathPrefix := strings.TrimSpace(entry)

		if left, right, found := strings.Cut(entry, ":"); found && strings.TrimSpace(right) != "" {
			category = normalizeWAFCategory(left)
			pathPrefix = strings.TrimSpace(right)
		}

		if pathPrefix == "" {
			continue
		}
		if !strings.HasPrefix(pathPrefix, "/") {
			pathPrefix = "/" + pathPrefix
		}

		rules = append(rules, WAFAllowRule{
			Category:   category,
			PathPrefix: pathPrefix,
		})
	}

	return rules
}

func IsWAFAllowed(rules []WAFAllowRule, category, path string) bool {
	if path == "" {
		path = "/"
	}

	category = normalizeWAFCategory(category)
	for _, rule := range rules {
		if rule.PathPrefix == "" || !pathPrefixMatches(path, rule.PathPrefix) {
			continue
		}
		if rule.Category == "*" || rule.Category == category {
			return true
		}
	}

	return false
}

func pathPrefixMatches(requestPath, prefix string) bool {
	if prefix == "/" || requestPath == prefix {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(requestPath, prefix)
	}
	return strings.HasPrefix(requestPath, prefix+"/")
}

func canonicalHost(hostPort string) string {
	value := strings.ToLower(strings.TrimSpace(hostPort))
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "*.") {
		return "*." + strings.TrimSuffix(strings.TrimPrefix(value, "*."), ".")
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else if strings.Count(value, ":") == 1 {
		if host, port, found := strings.Cut(value, ":"); found {
			if _, portErr := strconv.Atoi(port); portErr == nil {
				value = host
			}
		}
	}
	value = strings.Trim(value, "[]")
	return strings.TrimSuffix(value, ".")
}

func validAllowedHostPattern(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n\t /\\@") {
		return false
	}
	if strings.Contains(value, "*") && (!strings.HasPrefix(value, "*.") || strings.Count(value, "*") != 1) {
		return false
	}
	host := strings.TrimPrefix(canonicalHost(value), "*.")
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func validHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			return false
		}
	}
	return true
}

func validWebSocketOriginPattern(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || value == "*" || strings.ContainsAny(value, "\r\n\t \\@") {
		return false
	}
	if strings.Contains(value, "://") {
		scheme, host, found := strings.Cut(value, "://")
		if !found || (scheme != "http" && scheme != "https") || host == "" || strings.Contains(host, "/") {
			return false
		}
		value = host
	}
	if strings.Contains(value, "/") {
		return false
	}
	host := strings.TrimPrefix(value, "*.")
	if strings.Contains(host, "*") || host == "" {
		return false
	}
	return validAllowedHostPattern(host)
}

func normalizeWAFCategory(category string) string {
	clean := strings.TrimSpace(category)
	if clean == "" || clean == "*" {
		return "*"
	}

	fields := strings.Fields(clean)
	if len(fields) > 0 {
		clean = fields[0]
	}

	return strings.ToUpper(clean)
}
