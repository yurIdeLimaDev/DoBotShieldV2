package middleware

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"dobotshield/blocklist"
	"dobotshield/config"
	"dobotshield/ratelimit"
	"dobotshield/traininglog"
	"dobotshield/utils"
	"dobotshield/waf"
)

func BuildProxy(cfg config.Config) (*httputil.ReverseProxy, error) {
	return BuildProxyWithRules(cfg, nil)
}

// BuildProxyWithRules constructs the HTTP reverse proxy and attaches the
// immutable operator rule set to both request and response inspection.
func BuildProxyWithRules(cfg config.Config, customRules *waf.CustomRuleSet) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(cfg.TargetURL)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("TARGET_URL must be an absolute URL")
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("TARGET_URL scheme must be http or https")
	}
	if target.User != nil || target.Fragment != "" {
		return nil, fmt.Errorf("TARGET_URL must not contain credentials or a fragment")
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Director = nil
	proxy.Rewrite = func(proxyReq *httputil.ProxyRequest) {
		proxyReq.SetURL(target)
		if cfg.PreserveHost {
			proxyReq.Out.Host = proxyReq.In.Host
		}

		for _, header := range []string{
			"Forwarded", "Proxy", "Proxy-Connection", "X-HTTP-Method", "X-HTTP-Method-Override",
			"X-Method-Override", "X-Original-URL", "X-Rewrite-URL",
		} {
			proxyReq.Out.Header.Del(header)
		}

		// ReverseProxy removes forwarding headers before Rewrite. Restore only
		// the sanitized values produced by injectForwardedHeaders; unlike the
		// legacy Director path, Rewrite does not append RemoteAddr a second time.
		for _, header := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
			if values := proxyReq.In.Header.Values(header); len(values) > 0 {
				proxyReq.Out.Header[header] = append([]string(nil), values...)
			}
		}

		if cfg.ResponseWAFEnabled() {
			proxyReq.Out.Header.Del("Accept-Encoding")
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		hardenResponseHeaders(resp, cfg)
		inspectBackendResponse(resp, cfg, customRules)
		return nil
	}

	proxy.Transport = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    20,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		DisableCompression:     cfg.ResponseWAFEnabled(),
		MaxResponseHeaderBytes: effectiveResponseHeaderLimit(cfg.MaxHeaderBytes),
		// InsecureSkipVerify is an explicit compatibility escape hatch for
		// legacy upstreams and remains false by default.
		TLSClientConfig: &tls.Config{ // #nosec G402 -- controlled by documented operator configuration
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		requestID := r.Header.Get("X-Request-ID")
		clientIP := r.Header.Get("X-Real-IP")
		if requestID == "" {
			requestID = utils.NewRequestID()
		}
		utils.LogEventWithRequestID(requestID, "PROXY_ERROR", clientIP, err.Error(), r.URL.Path)
		secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
		applyLocalSecurityHeaders(w.Header(), cfg, secure)
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("X-DoBotShield-Action", "Proxy-Error")
		writeJSONError(w, http.StatusBadGateway, "Bad Gateway", "Backend unavailable")
	}

	return proxy, nil
}

func effectiveResponseHeaderLimit(configured int) int64 {
	if configured <= 0 {
		return 64 * 1024
	}
	return int64(configured)
}

func MakeSecureHandler(proxy *httputil.ReverseProxy, fw *ratelimit.Manager, bl *blocklist.List, cfg config.Config) http.HandlerFunc {
	return MakeSecureHandlerWithProtection(proxy, nil, fw, bl, cfg, nil)
}

// MakeSecureHandlerWithProtection applies common HTTP controls and dispatches
// WebSocket upgrades to the message-inspecting proxy.
func MakeSecureHandlerWithProtection(proxy *httputil.ReverseProxy, webSocketProxy *WebSocketProxy, fw *ratelimit.Manager, bl *blocklist.List, cfg config.Config, customRules *waf.CustomRuleSet) http.HandlerFunc {
	maxConcurrent := cfg.MaxConcurrentRequests
	if maxConcurrent <= 0 {
		maxConcurrent = 1000
	}
	requestSlots := make(chan struct{}, maxConcurrent)

	return func(w http.ResponseWriter, r *http.Request) {
		requestID := utils.GetOrCreateRequestID(r)
		directIP := utils.GetRealIP(r)
		directTrusted := utils.IsTrustedProxy(directIP, cfg.TrustedProxies)

		w.Header().Set("X-Request-ID", requestID)
		r.Header.Set("X-Request-ID", requestID)
		applyLocalSecurityHeaders(w.Header(), cfg, requestUsesHTTPS(r, directTrusted))
		select {
		case requestSlots <- struct{}{}:
			defer func() { <-requestSlots }()
		default:
			utils.LogEventWithRequestID(requestID, "CAPACITY_BLOCK", directIP, "global request capacity reached", r.URL.Path)
			w.Header().Set("X-DoBotShield-Action", "Blocked-Capacity")
			w.Header().Set("Retry-After", "1")
			writeJSONError(w, http.StatusServiceUnavailable, "Service Unavailable", "Proxy request capacity reached")
			return
		}

		if violation := waf.CheckProtocol(r, waf.ProtocolLimits{
			MaxURLLength:   cfg.MaxURLLength,
			MaxHeaderBytes: cfg.MaxHeaderBytes,
			MaxHeaderCount: cfg.MaxHeaderCount,
		}); violation != nil {
			utils.LogEventWithRequestID(requestID, "PROTOCOL_BLOCK", directIP, violation.Details+" ("+violation.Rule+")", r.URL.Path)
			w.Header().Set("X-DoBotShield-Action", "Blocked-Protocol")
			writeJSONError(w, violation.Status, "Invalid Request", "Request rejected by HTTP security policy")
			return
		}

		clientIP := utils.GetClientIP(r, cfg.TrustedProxies)

		if !cfg.HostAllowed(r.Host) {
			utils.LogEventWithRequestID(requestID, "HOST_BLOCK", clientIP, "host not allowlisted", r.URL.Path)
			w.Header().Set("X-DoBotShield-Action", "Blocked-Host")
			writeJSONError(w, http.StatusMisdirectedRequest, "Misdirected Request", "Host is not allowed")
			return
		}

		if bl.Contains(clientIP) {
			utils.LogEventWithRequestID(requestID, "IP_BLOCK", clientIP, "blocked IP", r.URL.Path)
			w.Header().Set("X-DoBotShield-Action", "Blocked-IP")
			writeJSONError(w, http.StatusForbidden, "Forbidden", "Access denied")
			return
		}

		if !cfg.MethodAllowed(r.Method) {
			utils.LogEventWithRequestID(requestID, "METHOD_BLOCK", clientIP, r.Method, r.URL.Path)
			w.Header().Set("X-DoBotShield-Action", "Blocked-Method")
			w.Header().Set("Allow", strings.Join(cfg.EffectiveAllowedMethods(), ", "))
			writeJSONError(w, http.StatusMethodNotAllowed, "Method Not Allowed", "HTTP method is not allowed")
			return
		}

		if cfg.EnableRateLimit {
			allowed, reason := fw.Allow(clientIP)
			if !allowed {
				utils.LogEventWithRequestID(requestID, "DoS_BLOCK", clientIP, reason, r.URL.Path)
				w.Header().Set("X-DoBotShield-Action", "Blocked-DoS")
				w.Header().Set("Retry-After", "30")
				http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
				return
			}
			defer fw.Release(clientIP)
		}

		var bodyBytes []byte
		if !isWebSocketUpgrade(r) {
			var blocked bool
			bodyBytes, blocked = readBoundedRequestBody(w, r, cfg.MaxBodySize, requestID, clientIP)
			if blocked {
				return
			}
		}

		if cfg.RequestWAFEnabled() {
			if blocked := inspectRequest(w, r, bodyBytes, cfg, customRules, requestID, clientIP); blocked {
				return
			}
		}

		injectForwardedHeaders(r, clientIP, directIP, directTrusted)

		utils.LogAccess(requestID, r.Method, r.URL.Path, clientIP)
		if isWebSocketUpgrade(r) && cfg.EnableWebSocketProtection {
			if webSocketProxy == nil {
				utils.LogEventWithRequestID(requestID, "WEBSOCKET_ERROR", clientIP, "WebSocket protection is unavailable", r.URL.Path)
				w.Header().Set("X-DoBotShield-Action", "WebSocket-Unavailable")
				writeJSONError(w, http.StatusServiceUnavailable, "Service Unavailable", "WebSocket protection is unavailable")
				return
			}
			webSocketProxy.ServeHTTP(w, r, webSocketContext{requestID: requestID, clientIP: clientIP})
			return
		}
		clearLocalResponseHeaders(w.Header())
		proxy.ServeHTTP(w, r)
	}
}

func inspectRequest(w http.ResponseWriter, r *http.Request, bodyBytes []byte, cfg config.Config, customRules *waf.CustomRuleSet, requestID, clientIP string) bool {
	inspectionBody, violation := waf.DecodeBodyForInspection(r.Header.Get("Content-Encoding"), bodyBytes, cfg.MaxDecodedBodySize)
	if violation != nil {
		return handleRequestDetection(w, r, cfg, requestID, clientIP, bodyBytes, violation.Details, violation.Rule, violation.Status)
	}

	if malicious, details, rule := waf.CheckRequest(r, inspectionBody); malicious {
		return handleRequestDetection(w, r, cfg, requestID, clientIP, inspectionBody, details, rule, http.StatusBadRequest)
	}
	if malicious, details, rule := customRules.CheckRequest(r, inspectionBody); malicious {
		return handleRequestDetection(w, r, cfg, requestID, clientIP, inspectionBody, details, rule, http.StatusBadRequest)
	}

	return false
}

func readBoundedRequestBody(w http.ResponseWriter, r *http.Request, limit int64, requestID, clientIP string) ([]byte, bool) {
	if r.Body == nil {
		return nil, false
	}
	if limit <= 0 {
		limit = 1024 * 1024
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			utils.LogEventWithRequestID(requestID, "BODY_BLOCK", clientIP, "Request body too large", r.URL.Path)
			w.Header().Set("X-DoBotShield-Action", "Blocked-Body-Size")
			writeJSONError(w, http.StatusRequestEntityTooLarge, "Payload Too Large", "Request body exceeds the configured limit")
			return nil, true
		}
		utils.LogEventWithRequestID(requestID, "BODY_READ_ERROR", clientIP, err.Error(), r.URL.Path)
		writeJSONError(w, http.StatusBadRequest, "Bad Request", "Request body could not be read")
		return nil, true
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return bodyBytes, false
}

func handleRequestDetection(w http.ResponseWriter, r *http.Request, cfg config.Config, requestID, clientIP string, inspectedBody []byte, details, rule string, status int) bool {
	if config.IsWAFAllowed(cfg.WAFAllowlist, details, r.URL.Path) {
		utils.LogEventWithRequestID(requestID, "WAF_ALLOW", clientIP, details, r.URL.Path)
		return false
	}
	if cfg.WAFBlocks() {
		utils.LogEventWithRequestID(requestID, "WAF_BLOCK", clientIP, details+" ("+rule+")", r.URL.Path)
		recordTrainingRequest(r, inspectedBody, requestID, clientIP, details, rule, "blocked", cfg.TrainingRedactSensitive)
		w.Header().Set("X-DoBotShield-Action", "Blocked-WAF")
		writeJSONError(w, status, "Security Violation", "Request blocked by security policy")
		return true
	}
	utils.LogEventWithRequestID(requestID, "WAF_DETECT", clientIP, details+" ("+rule+")", r.URL.Path)
	recordTrainingRequest(r, inspectedBody, requestID, clientIP, details, rule, "detected", cfg.TrainingRedactSensitive)
	return false
}

// recordTrainingRequest records details for a blocked request or a monitor-mode
// detection. It is observability-only and cannot change the WAF decision.
func recordTrainingRequest(r *http.Request, bodyBytes []byte, requestID, clientIP, details, rule, action string, redactSensitive bool) {
	if !traininglog.Enabled() {
		return
	}

	detection := waf.DescribeBlock(r, bodyBytes, details, rule)
	if redactSensitive {
		detection = waf.RedactDetection(detection)
	}
	traininglog.Record(traininglog.Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		RequestID: requestID,
		IP:        clientIP,
		Method:    r.Method,
		Path:      r.URL.Path,
		Phase:     "request",
		Action:    action,
		Category:  detection.Category,
		Location:  detection.Location,
		Rule:      detection.Rule,
		Payload:   detection.Payload,
		Variants:  detection.Variants,
	})
}

// recordTrainingResponse records a backend response leak. Its payload is the
// response fragment that matched the output rule.
func recordTrainingResponse(requestID, clientIP, path, details, rule string, bodyBytes []byte, action string, redactSensitive bool) {
	if !traininglog.Enabled() {
		return
	}

	category, location := waf.SplitDetails(details)
	payload := string(bodyBytes)
	if redactSensitive {
		detection := waf.RedactDetection(waf.Detection{Category: category, Location: location, Rule: rule, Payload: payload})
		payload = detection.Payload
	}
	traininglog.Record(traininglog.Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		RequestID: requestID,
		IP:        clientIP,
		Path:      path,
		Phase:     "response",
		Action:    action,
		Category:  category,
		Location:  location,
		Rule:      rule,
		Payload:   payload,
	})
}

func hardenResponseHeaders(resp *http.Response, cfg config.Config) {
	requestID := ""
	if resp.Request != nil {
		requestID = resp.Request.Header.Get("X-Request-ID")
	}

	resp.Header.Del("Server")
	resp.Header.Del("X-Powered-By")
	resp.Header.Del("X-AspNet-Version")
	resp.Header.Del("X-AspNetMvc-Version")

	resp.Header.Set("X-DoBotShield-Action", "Forwarded")
	if requestID != "" {
		resp.Header.Set("X-Request-ID", requestID)
	}
	secure := false
	if resp.Request != nil {
		secure = strings.EqualFold(resp.Request.Header.Get("X-Forwarded-Proto"), "https")
	}
	applyCommonSecurityHeaders(resp.Header, cfg, secure)
	if cfg.HardenCookies {
		hardenSetCookies(resp.Header, secure)
	}
}

func inspectBackendResponse(resp *http.Response, cfg config.Config, customRules *waf.CustomRuleSet) {
	if !cfg.ResponseWAFEnabled() || resp == nil {
		return
	}

	requestID, clientIP, path := responseLogContext(resp)
	if resp.StatusCode != http.StatusSwitchingProtocols && (resp.Request == nil || !isWebSocketUpgrade(resp.Request)) {
		if malicious, details, rule := customRules.CheckResponseHeaders(resp); malicious {
			if handleResponseDetection(resp, cfg, requestID, clientIP, path, details, rule, nil) {
				return
			}
		}
	}
	if !shouldInspectBackendResponse(resp, cfg) {
		return
	}

	inspectionLimit := cfg.ResponseInspectionLimit
	if inspectionLimit <= 0 {
		inspectionLimit = 1024 * 1024
	}
	bodyBytes, overLimit, err := readResponseForInspection(resp, inspectionLimit)
	if err != nil {
		utils.LogEventWithRequestID(requestID, "RESPONSE_READ_ERROR", clientIP, err.Error(), path)
		return
	}
	inspectionBytes := bodyBytes
	if overLimit && int64(len(inspectionBytes)) > inspectionLimit {
		inspectionBytes = inspectionBytes[:inspectionLimit]
	}

	malicious, details, rule := waf.CheckResponseWithOptions(resp, inspectionBytes, waf.ResponseOptions{
		DetectActiveXSS:         cfg.EnableResponseXSS,
		DiagnosticsOnErrorsOnly: cfg.ResponseDiagnosticsErrorsOnly,
	})
	if !malicious {
		malicious, details, rule = customRules.CheckResponseBody(inspectionBytes)
	}
	if malicious {
		if handleResponseDetection(resp, cfg, requestID, clientIP, path, details, rule, inspectionBytes) {
			return
		}
	}
	if overLimit {
		utils.LogEventWithRequestID(requestID, "RESPONSE_INSPECTION_PARTIAL", clientIP, "Inspected the bounded response prefix; the remainder was forwarded without inspection", path)
	}
}

func handleResponseDetection(resp *http.Response, cfg config.Config, requestID, clientIP, path, details, rule string, inspected []byte) bool {
	if config.IsWAFAllowed(cfg.WAFAllowlist, details, path) {
		utils.LogEventWithRequestID(requestID, "RESPONSE_WAF_ALLOW", clientIP, details, path)
		return false
	}
	if cfg.WAFBlocks() {
		utils.LogEventWithRequestID(requestID, "RESPONSE_WAF_BLOCK", clientIP, details, path)
		recordTrainingResponse(requestID, clientIP, path, details, rule, responseDetectionPayload(resp, details, inspected), "blocked", cfg.TrainingRedactSensitive)
		blockBackendResponse(resp)
		return true
	}
	utils.LogEventWithRequestID(requestID, "RESPONSE_WAF_DETECT", clientIP, details, path)
	recordTrainingResponse(requestID, clientIP, path, details, rule, responseDetectionPayload(resp, details, inspected), "detected", cfg.TrainingRedactSensitive)
	return false
}

func responseDetectionPayload(resp *http.Response, details string, fallback []byte) []byte {
	const marker = " in Response Header "
	index := strings.Index(details, marker)
	if index < 0 || resp == nil {
		return fallback
	}
	name := strings.TrimSpace(details[index+len(marker):])
	if name == "" {
		return fallback
	}
	return []byte(strings.Join(resp.Header.Values(name), " | "))
}

func shouldInspectBackendResponse(resp *http.Response, cfg config.Config) bool {
	if !cfg.ResponseWAFEnabled() || resp == nil || resp.Body == nil {
		return false
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return false
	}
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return false
	}
	if resp.Request != nil && strings.EqualFold(resp.Request.Method, http.MethodHead) {
		return false
	}
	if resp.Request != nil && isWebSocketUpgrade(resp.Request) {
		return false
	}
	if encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return false
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Disposition")), "attachment") {
		return false
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if contentType == "" {
		return true
	}

	return strings.HasPrefix(contentType, "text/") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "xml") ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "x-www-form-urlencoded")
}

func readResponseForInspection(resp *http.Response, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		limit = 1024 * 1024
	}

	originalBody := resp.Body
	bodyBytes, err := io.ReadAll(io.LimitReader(originalBody, limit+1))
	if err != nil {
		resp.Body = readCloser{
			Reader: io.MultiReader(bytes.NewReader(bodyBytes), originalBody),
			Closer: originalBody,
		}
		return nil, false, err
	}

	if int64(len(bodyBytes)) > limit {
		resp.Body = readCloser{
			Reader: io.MultiReader(bytes.NewReader(bodyBytes), originalBody),
			Closer: originalBody,
		}
		return bodyBytes, true, nil
	}

	_ = originalBody.Close()
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))
	resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	return bodyBytes, false, nil
}

func blockBackendResponse(resp *http.Response) {
	body := []byte("{\"error\":\"Security Violation\",\"reason\":\"Backend response blocked by security policy\"}\n")

	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	resp.StatusCode = http.StatusBadGateway
	resp.Status = "502 Bad Gateway"
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	safeHeaders := make(http.Header)
	for _, name := range []string{
		"X-Request-ID", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
		"Permissions-Policy", "X-Permitted-Cross-Domain-Policies", "Strict-Transport-Security",
		"Content-Security-Policy",
	} {
		if values := resp.Header.Values(name); len(values) > 0 {
			for _, value := range values {
				safeHeaders.Add(name, value)
			}
		}
	}
	resp.Header = safeHeaders
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Set("X-DoBotShield-Action", "Blocked-Response-WAF")
}

func responseLogContext(resp *http.Response) (string, string, string) {
	if resp == nil || resp.Request == nil {
		return utils.NewRequestID(), "", ""
	}

	requestID := resp.Request.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = utils.NewRequestID()
	}

	return requestID, resp.Request.Header.Get("X-Real-IP"), resp.Request.URL.Path
}

type readCloser struct {
	io.Reader
	io.Closer
}

func isBlockedMethod(method string) bool {
	return strings.EqualFold(method, http.MethodTrace) || strings.EqualFold(method, "TRACK")
}

func isWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		headerHasToken(r.Header.Get("Connection"), "upgrade")
}

func headerHasToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func injectForwardedHeaders(r *http.Request, clientIP, directIP string, directTrusted bool) {
	forwardedProto := "http"
	if requestUsesHTTPS(r, directTrusted) {
		forwardedProto = "https"
	}
	r.Header.Del("Forwarded")
	r.Header.Del("X-Forwarded-For")

	if directTrusted && clientIP != "" && clientIP != directIP {
		r.Header.Set("X-Forwarded-For", clientIP+", "+directIP)
	} else {
		r.Header.Set("X-Forwarded-For", directIP)
	}

	r.Header.Set("X-Real-IP", clientIP)
	r.Header.Set("X-DoBotShield-Request-ID", r.Header.Get("X-Request-ID"))
	r.Header.Set("X-Forwarded-Proto", forwardedProto)
	r.Header.Set("X-Forwarded-Host", r.Host)
}

func writeJSONError(w http.ResponseWriter, status int, message, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  message,
		"reason": reason,
	})
}

func applyLocalSecurityHeaders(header http.Header, cfg config.Config, secure bool) {
	applyCommonSecurityHeaders(header, cfg, secure)
}

func applyCommonSecurityHeaders(header http.Header, cfg config.Config, secure bool) {
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	header.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
	header.Set("X-Permitted-Cross-Domain-Policies", "none")
	if secure {
		header.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	} else {
		header.Del("Strict-Transport-Security")
	}
	if cfg.ContentSecurityPolicy != "" {
		header.Set("Content-Security-Policy", cfg.ContentSecurityPolicy)
	}
}

// clearLocalResponseHeaders removes headers provisionally set for local errors
// before ReverseProxy copies the finalized upstream response. ModifyResponse or
// ErrorHandler then installs exactly one authoritative set.
func clearLocalResponseHeaders(header http.Header) {
	for _, name := range []string{
		"X-Request-ID",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Permissions-Policy",
		"X-Permitted-Cross-Domain-Policies",
		"Strict-Transport-Security",
		"Content-Security-Policy",
	} {
		header.Del(name)
	}
}

func requestUsesHTTPS(r *http.Request, directTrusted bool) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if !directTrusted {
		return false
	}
	values := r.Header.Values("X-Forwarded-Proto")
	if len(values) != 1 {
		return false
	}
	proto := strings.ToLower(strings.TrimSpace(strings.Split(values[0], ",")[0]))
	return proto == "https"
}

func hardenSetCookies(header http.Header, secure bool) {
	cookies := header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	header.Del("Set-Cookie")
	for _, cookie := range cookies {
		if !cookieHasAttribute(cookie, "httponly") {
			cookie += "; HttpOnly"
		}
		if !cookieHasAttribute(cookie, "samesite") {
			cookie += "; SameSite=Lax"
		}
		if secure && !cookieHasAttribute(cookie, "secure") {
			cookie += "; Secure"
		}
		header.Add("Set-Cookie", cookie)
	}
}

func cookieHasAttribute(cookie, attribute string) bool {
	parts := strings.Split(cookie, ";")
	for _, part := range parts[1:] {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		if strings.EqualFold(name, attribute) {
			return true
		}
	}
	return false
}
