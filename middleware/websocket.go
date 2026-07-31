package middleware

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"dobotshield/config"
	"dobotshield/traininglog"
	"dobotshield/utils"
	"dobotshield/waf"

	"github.com/coder/websocket"
)

const maxWebSocketSubprotocols = 32

// WebSocketProxy terminates both sides of an RFC 6455 connection so complete
// application messages can be bounded and inspected before being forwarded.
type WebSocketProxy struct {
	cfg         config.Config
	target      *url.URL
	client      *http.Client
	customRules *waf.CustomRuleSet
}

type webSocketContext struct {
	requestID string
	clientIP  string
}

type webSocketPumpResult struct {
	err    error
	code   websocket.StatusCode
	reason string
}

type webSocketDirection struct {
	phase      string
	eventLabel string
	clientSide bool
}

// BuildWebSocketProxy builds a dedicated upstream client with no environment
// proxy or redirects. This prevents a backend redirect from changing the
// configured trust boundary.
func BuildWebSocketProxy(cfg config.Config, customRules *waf.CustomRuleSet) (*WebSocketProxy, error) {
	if !cfg.EnableWebSocketProtection {
		return nil, nil
	}
	target, err := url.Parse(cfg.TargetURL)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("TARGET_URL must be an absolute URL")
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("TARGET_URL scheme must be http or https")
	}

	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:      false,
		MaxIdleConns:           20,
		MaxIdleConnsPerHost:    20,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		DisableCompression:     true,
		MaxResponseHeaderBytes: effectiveResponseHeaderLimit(cfg.MaxHeaderBytes),
		TLSClientConfig: &tls.Config{ // #nosec G402 -- explicit compatibility option, false by default
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
	}

	return &WebSocketProxy{
		cfg:         cfg,
		target:      target,
		customRules: customRules,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (proxy *WebSocketProxy) ServeHTTP(w http.ResponseWriter, r *http.Request, metadata webSocketContext) {
	if err := validateWebSocketHandshake(r); err != nil {
		utils.LogEventWithRequestID(metadata.requestID, "WEBSOCKET_HANDSHAKE_BLOCK", metadata.clientIP, err.Error(), r.URL.Path)
		w.Header().Set("X-DoBotShield-Action", "Blocked-WebSocket-Handshake")
		writeJSONError(w, http.StatusBadRequest, "Invalid Request", "WebSocket handshake rejected by security policy")
		return
	}
	if err := authorizeWebSocketOrigin(r, proxy.cfg.WebSocketAllowedOrigins); err != nil {
		utils.LogEventWithRequestID(metadata.requestID, "WEBSOCKET_ORIGIN_BLOCK", metadata.clientIP, err.Error(), r.URL.Path)
		w.Header().Set("X-DoBotShield-Action", "Blocked-WebSocket-Origin")
		writeJSONError(w, http.StatusForbidden, "Forbidden", "WebSocket origin is not allowed")
		return
	}

	protocols := webSocketSubprotocols(r.Header.Values("Sec-WebSocket-Protocol"))
	upstreamHeaders := webSocketUpstreamHeaders(r.Header)
	upstreamURL := proxy.upstreamURL(r.URL)
	upstreamHost := ""
	if proxy.cfg.PreserveHost {
		upstreamHost = r.Host
	}

	dialContext, cancelDial := context.WithTimeout(r.Context(), 10*time.Second)
	upstream, response, err := websocket.Dial(dialContext, upstreamURL.String(), &websocket.DialOptions{
		HTTPClient:      proxy.client,
		HTTPHeader:      upstreamHeaders,
		Host:            upstreamHost,
		Subprotocols:    protocols,
		CompressionMode: websocket.CompressionDisabled,
	})
	cancelDial()
	if err != nil {
		status := "no HTTP response"
		if response != nil {
			status = response.Status
		}
		utils.LogEventWithRequestID(metadata.requestID, "WEBSOCKET_UPSTREAM_ERROR", metadata.clientIP, status, r.URL.Path)
		w.Header().Set("X-DoBotShield-Action", "WebSocket-Proxy-Error")
		writeJSONError(w, http.StatusBadGateway, "Bad Gateway", "WebSocket backend unavailable")
		return
	}

	acceptedProtocols := []string(nil)
	if selected := upstream.Subprotocol(); selected != "" {
		acceptedProtocols = []string{selected}
	}
	copyWebSocketResponseHeaders(w.Header(), response.Header, proxy.cfg, strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
	w.Header().Set("X-Request-ID", metadata.requestID)
	w.Header().Set("X-DoBotShield-Action", "WebSocket-Forwarded")
	client, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:    acceptedProtocols,
		OriginPatterns:  proxy.cfg.WebSocketAllowedOrigins,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		_ = upstream.CloseNow()
		utils.LogEventWithRequestID(metadata.requestID, "WEBSOCKET_HANDSHAKE_ERROR", metadata.clientIP, err.Error(), r.URL.Path)
		return
	}

	limit := proxy.cfg.WebSocketMaxMessageSize
	client.SetReadLimit(limit)
	upstream.SetReadLimit(limit)
	utils.LogEventWithRequestID(metadata.requestID, "WEBSOCKET_OPEN", metadata.clientIP, "message inspection enabled", r.URL.Path)

	sessionContext, cancelSession := context.WithCancel(context.Background())
	results := make(chan webSocketPumpResult, 2)
	go func() {
		results <- proxy.pump(sessionContext, client, upstream, r.URL.Path, metadata, webSocketDirection{
			phase: "websocket-client", eventLabel: "CLIENT", clientSide: true,
		})
	}()
	go func() {
		results <- proxy.pump(sessionContext, upstream, client, r.URL.Path, metadata, webSocketDirection{
			phase: "websocket-server", eventLabel: "SERVER", clientSide: false,
		})
	}()

	result := <-results
	code, reason := webSocketCloseDecision(result)
	closeWebSocketPair(client, upstream, code, reason)
	cancelSession()
	select {
	case <-results:
	case <-time.After(2 * time.Second):
	}
	utils.LogEventWithRequestID(metadata.requestID, "WEBSOCKET_CLOSE", metadata.clientIP, fmt.Sprintf("code=%d", code), r.URL.Path)
}

func (proxy *WebSocketProxy) pump(ctx context.Context, source, destination *websocket.Conn, requestPath string, metadata webSocketContext, direction webSocketDirection) webSocketPumpResult {
	bucket := newWebSocketMessageBucket(proxy.cfg.WebSocketMessagesPerSecond, proxy.cfg.WebSocketBurstLimit)
	for {
		messageType, message, err := source.Read(ctx)
		if err != nil {
			if errors.Is(err, websocket.ErrMessageTooBig) || websocket.CloseStatus(err) == websocket.StatusMessageTooBig {
				utils.LogEventWithRequestID(metadata.requestID, "WEBSOCKET_SIZE_BLOCK", metadata.clientIP, direction.eventLabel+" message exceeded limit", requestPath)
				return webSocketPumpResult{err: err, code: websocket.StatusMessageTooBig, reason: "Message exceeds security limit"}
			}
			return webSocketPumpResult{err: err}
		}
		if !bucket.Allow() {
			utils.LogEventWithRequestID(metadata.requestID, "WEBSOCKET_RATE_BLOCK", metadata.clientIP, direction.eventLabel+" message rate exceeded", requestPath)
			return webSocketPumpResult{code: websocket.StatusTryAgainLater, reason: "Message rate exceeds security limit"}
		}

		inspect := messageType == websocket.MessageText || proxy.cfg.WebSocketInspectBinary
		if inspect {
			blocked := proxy.inspectMessage(message, requestPath, metadata, direction)
			if blocked {
				return webSocketPumpResult{code: websocket.StatusPolicyViolation, reason: "Message blocked by security policy"}
			}
		}
		if err := destination.Write(ctx, messageType, message); err != nil {
			return webSocketPumpResult{err: err}
		}
	}
}

func (proxy *WebSocketProxy) inspectMessage(message []byte, requestPath string, metadata webSocketContext, direction webSocketDirection) bool {
	var malicious bool
	var details, rule string

	if direction.clientSide && proxy.cfg.RequestWAFEnabled() {
		malicious, details, rule = waf.CheckWebSocketClientMessage(message)
		if !malicious {
			malicious, details, rule = proxy.customRules.CheckMessage(direction.phase, message)
		}
	} else if !direction.clientSide && proxy.cfg.ResponseWAFEnabled() {
		malicious, details, rule = waf.CheckWebSocketServerMessage(message, proxy.cfg.EnableResponseXSS, !proxy.cfg.ResponseDiagnosticsErrorsOnly)
		if !malicious {
			malicious, details, rule = proxy.customRules.CheckMessage(direction.phase, message)
		}
	}
	if !malicious {
		return false
	}
	if config.IsWAFAllowed(proxy.cfg.WAFAllowlist, details, requestPath) {
		utils.LogEventWithRequestID(metadata.requestID, "WEBSOCKET_WAF_ALLOW", metadata.clientIP, details, requestPath)
		return false
	}

	action := "detected"
	event := "WEBSOCKET_WAF_DETECT"
	if proxy.cfg.WAFBlocks() {
		action = "blocked"
		event = "WEBSOCKET_WAF_BLOCK"
	}
	utils.LogEventWithRequestID(metadata.requestID, event, metadata.clientIP, details+" ("+rule+")", requestPath)
	recordTrainingWebSocket(metadata, requestPath, direction.phase, message, details, rule, action, proxy.cfg.TrainingRedactSensitive)
	return proxy.cfg.WAFBlocks()
}

func (proxy *WebSocketProxy) upstreamURL(requestURL *url.URL) *url.URL {
	result := *proxy.target
	if result.Scheme == "https" {
		result.Scheme = "wss"
	} else {
		result.Scheme = "ws"
	}
	result.Path, result.RawPath = joinURLPath(proxy.target, requestURL)
	switch {
	case proxy.target.RawQuery == "":
		result.RawQuery = requestURL.RawQuery
	case requestURL.RawQuery == "":
		result.RawQuery = proxy.target.RawQuery
	default:
		result.RawQuery = proxy.target.RawQuery + "&" + requestURL.RawQuery
	}
	return &result
}

func joinURLPath(a, b *url.URL) (pathValue, rawPath string) {
	if a.RawPath == "" && b.RawPath == "" {
		aslash := strings.HasSuffix(a.Path, "/")
		bslash := strings.HasPrefix(b.Path, "/")
		switch {
		case aslash && bslash:
			return a.Path + b.Path[1:], ""
		case !aslash && !bslash:
			return a.Path + "/" + b.Path, ""
		default:
			return a.Path + b.Path, ""
		}
	}

	aPath := a.EscapedPath()
	bPath := b.EscapedPath()
	aslash := strings.HasSuffix(aPath, "/")
	bslash := strings.HasPrefix(bPath, "/")
	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], aPath + bPath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, aPath + "/" + bPath
	default:
		return a.Path + b.Path, aPath + bPath
	}
}

func validateWebSocketHandshake(r *http.Request) error {
	if r == nil || !r.ProtoAtLeast(1, 1) {
		return fmt.Errorf("handshake requires HTTP/1.1 or newer")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return fmt.Errorf("unsupported WebSocket version")
	}
	keys := r.Header.Values("Sec-WebSocket-Key")
	if len(keys) != 1 {
		return fmt.Errorf("handshake requires exactly one WebSocket key")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keys[0]))
	if err != nil || len(decoded) != 16 {
		return fmt.Errorf("invalid WebSocket key")
	}
	protocols := webSocketSubprotocols(r.Header.Values("Sec-WebSocket-Protocol"))
	if len(protocols) > maxWebSocketSubprotocols {
		return fmt.Errorf("too many WebSocket subprotocols")
	}
	for _, protocol := range protocols {
		if len(protocol) > 128 || !validWebSocketToken(protocol) {
			return fmt.Errorf("invalid WebSocket subprotocol")
		}
	}
	return nil
}

func authorizeWebSocketOrigin(r *http.Request, allowedPatterns []string) error {
	origins := r.Header.Values("Origin")
	if len(origins) == 0 || strings.TrimSpace(origins[0]) == "" {
		return nil
	}
	if len(origins) != 1 {
		return fmt.Errorf("multiple Origin headers")
	}
	origin, err := url.Parse(origins[0])
	if err != nil || origin.Host == "" || (origin.Scheme != "http" && origin.Scheme != "https") {
		return fmt.Errorf("invalid Origin header")
	}
	if origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return fmt.Errorf("invalid Origin header components")
	}
	if strings.EqualFold(r.Host, origin.Host) {
		return nil
	}
	for _, pattern := range allowedPatterns {
		target := origin.Host
		if strings.Contains(pattern, "://") {
			target = origin.Scheme + "://" + origin.Host
		}
		matched, matchErr := path.Match(strings.ToLower(pattern), strings.ToLower(target))
		if matchErr == nil && matched {
			return nil
		}
	}
	return fmt.Errorf("origin host is not authorized")
}

func webSocketSubprotocols(values []string) []string {
	var protocols []string
	for _, value := range values {
		for _, protocol := range strings.Split(value, ",") {
			if clean := strings.TrimSpace(protocol); clean != "" {
				protocols = append(protocols, clean)
			}
		}
	}
	return protocols
}

func validWebSocketToken(value string) bool {
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			return false
		}
	}
	return value != ""
}

func webSocketUpstreamHeaders(source http.Header) http.Header {
	headers := source.Clone()
	for _, connectionValue := range source.Values("Connection") {
		for _, token := range strings.Split(connectionValue, ",") {
			headers.Del(strings.TrimSpace(token))
		}
	}
	for name := range headers {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "sec-websocket-") {
			headers.Del(name)
		}
	}
	for _, name := range []string{
		"Connection", "Upgrade", "Keep-Alive", "Proxy", "Proxy-Connection",
		"Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding",
	} {
		headers.Del(name)
	}
	return headers
}

func copyWebSocketResponseHeaders(destination, source http.Header, cfg config.Config, secure bool) {
	connectionTokens := make(map[string]struct{})
	for _, connectionValue := range source.Values("Connection") {
		for _, token := range strings.Split(connectionValue, ",") {
			connectionTokens[strings.ToLower(strings.TrimSpace(token))] = struct{}{}
		}
	}
	for name, values := range source {
		lower := strings.ToLower(name)
		if _, hopByHop := connectionTokens[lower]; hopByHop || strings.HasPrefix(lower, "sec-websocket-") {
			continue
		}
		switch lower {
		case "connection", "upgrade", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding",
			"server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-request-id", "x-dobotshield-action":
			continue
		}
		for _, value := range values {
			destination.Add(name, value)
		}
	}
	if cfg.HardenCookies {
		hardenSetCookies(destination, secure)
	}
	destination.Del("Server")
	destination.Del("X-Powered-By")
	destination.Del("X-AspNet-Version")
	destination.Del("X-AspNetMvc-Version")
	applyCommonSecurityHeaders(destination, cfg, secure)
}

func webSocketCloseDecision(result webSocketPumpResult) (websocket.StatusCode, string) {
	if result.code != 0 {
		return result.code, result.reason
	}
	if status := websocket.CloseStatus(result.err); status != -1 && status != websocket.StatusNoStatusRcvd && status != websocket.StatusAbnormalClosure {
		return status, "Connection closed"
	}
	if result.err == nil || errors.Is(result.err, context.Canceled) {
		return websocket.StatusNormalClosure, "Connection closed"
	}
	return websocket.StatusInternalError, "Connection terminated"
}

func closeWebSocketPair(first, second *websocket.Conn, code websocket.StatusCode, reason string) {
	var wait sync.WaitGroup
	wait.Add(2)
	for _, connection := range []*websocket.Conn{first, second} {
		go func(conn *websocket.Conn) {
			defer wait.Done()
			_ = conn.Close(code, reason)
		}(connection)
	}
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = first.CloseNow()
		_ = second.CloseNow()
	}
}

type webSocketMessageBucket struct {
	mu         sync.Mutex
	tokens     float64
	lastRefill time.Time
	rate       float64
	burst      float64
}

func newWebSocketMessageBucket(rate float64, burst int) *webSocketMessageBucket {
	return &webSocketMessageBucket{
		tokens:     float64(burst),
		lastRefill: time.Now(),
		rate:       rate,
		burst:      float64(burst),
	}
}

func (bucket *webSocketMessageBucket) Allow() bool {
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	now := time.Now()
	bucket.tokens += now.Sub(bucket.lastRefill).Seconds() * bucket.rate
	if bucket.tokens > bucket.burst {
		bucket.tokens = bucket.burst
	}
	bucket.lastRefill = now
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func recordTrainingWebSocket(metadata webSocketContext, requestPath, phase string, message []byte, details, rule, action string, redactSensitive bool) {
	if !traininglog.Enabled() {
		return
	}
	category, location := waf.SplitDetails(details)
	detection := waf.Detection{
		Category: category,
		Location: location,
		Rule:     rule,
		Payload:  string(message),
		Variants: waf.BuildVariants(string(message)),
	}
	if redactSensitive {
		detection = waf.RedactDetection(detection)
	}
	traininglog.Record(traininglog.Event{
		Timestamp: metadataTimestamp(),
		RequestID: metadata.requestID,
		IP:        metadata.clientIP,
		Path:      requestPath,
		Phase:     phase,
		Action:    action,
		Category:  detection.Category,
		Location:  detection.Location,
		Rule:      detection.Rule,
		Payload:   detection.Payload,
		Variants:  detection.Variants,
	})
}

func metadataTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
