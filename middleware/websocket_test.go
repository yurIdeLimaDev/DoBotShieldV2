package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dobotshield/blocklist"
	"dobotshield/config"
	"dobotshield/ratelimit"
	"dobotshield/waf"

	"github.com/coder/websocket"
)

func TestProtectedWebSocketForwardsBenignMessages(t *testing.T) {
	front, _ := protectedWebSocketTestServer(t, nil, nil)
	connection := dialWebSocketTestServer(t, front.URL, nil)
	defer connection.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, []byte("hello shield")); err != nil {
		t.Fatal(err)
	}
	messageType, message, err := connection.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.MessageText || string(message) != "hello shield" {
		t.Fatalf("unexpected echo: type=%v message=%q", messageType, message)
	}
}

func TestProtectedWebSocketForwardsSafeHandshakeHeaders(t *testing.T) {
	front, _ := protectedWebSocketTestServer(t, nil, nil, func(cfg *config.Config) {
		cfg.HardenCookies = true
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, response, err := websocket.Dial(ctx, strings.Replace(front.URL, "http://", "ws://", 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	cookie := response.Header.Get("Set-Cookie")
	if !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "SameSite=Lax") {
		t.Fatalf("expected hardened upstream handshake cookie, got %q", cookie)
	}
	if response.Header.Get("Server") != "" || response.Header.Get("X-Powered-By") != "" {
		t.Fatalf("backend fingerprint headers leaked: %v", response.Header)
	}
	if response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("X-DoBotShield-Action") != "WebSocket-Forwarded" {
		t.Fatalf("expected proxy security metadata, got %v", response.Header)
	}
}

func TestProtectedWebSocketBlocksClientAttackMessage(t *testing.T) {
	front, _ := protectedWebSocketTestServer(t, nil, nil)
	connection := dialWebSocketTestServer(t, front.URL, nil)
	defer connection.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, []byte(`<script>alert(document.cookie)</script>`)); err != nil {
		t.Fatal(err)
	}
	_, _, err := connection.Read(ctx)
	if status := websocket.CloseStatus(err); status != websocket.StatusPolicyViolation {
		t.Fatalf("expected policy-violation close, got status=%v err=%v", status, err)
	}
}

func TestProtectedWebSocketBlocksServerLeakMessage(t *testing.T) {
	backendBehavior := func(message []byte) []byte {
		return []byte("root:x:0:0:root:/root:/bin/bash")
	}
	front, _ := protectedWebSocketTestServer(t, nil, backendBehavior)
	connection := dialWebSocketTestServer(t, front.URL, nil)
	defer connection.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, []byte("profile")); err != nil {
		t.Fatal(err)
	}
	_, _, err := connection.Read(ctx)
	if status := websocket.CloseStatus(err); status != websocket.StatusPolicyViolation {
		t.Fatalf("expected server leak to close with policy violation, got status=%v err=%v", status, err)
	}
}

func TestProtectedWebSocketAppliesCustomRegex(t *testing.T) {
	rules, err := waf.CompileCustomRules(waf.CustomRulesFile{
		Version: 1,
		Rules: []waf.CustomRuleConfig{{
			ID: "operator-command", Phase: "websocket-client", Target: "message", Pattern: `(?i)tenant-admin:[0-9]{4}`,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	front, _ := protectedWebSocketTestServer(t, rules, nil)
	connection := dialWebSocketTestServer(t, front.URL, nil)
	defer connection.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, []byte("tenant-admin:1234")); err != nil {
		t.Fatal(err)
	}
	_, _, err = connection.Read(ctx)
	if status := websocket.CloseStatus(err); status != websocket.StatusPolicyViolation {
		t.Fatalf("expected custom rule to block, got status=%v err=%v", status, err)
	}
}

func TestProtectedWebSocketRejectsCrossOriginHandshake(t *testing.T) {
	front, _ := protectedWebSocketTestServer(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, response, err := websocket.Dial(ctx, strings.Replace(front.URL, "http://", "ws://", 1), &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": []string{"https://attacker.example"}},
	})
	if err == nil {
		t.Fatal("expected cross-origin handshake to be rejected")
	}
	if response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403, got response=%v err=%v", response, err)
	}
}

func TestProtectedWebSocketEnforcesMessageRate(t *testing.T) {
	mutate := func(cfg *config.Config) {
		cfg.WebSocketMessagesPerSecond = 0.01
		cfg.WebSocketBurstLimit = 1
	}
	front, _ := protectedWebSocketTestServer(t, nil, nil, mutate)
	connection := dialWebSocketTestServer(t, front.URL, nil)
	defer connection.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := connection.Read(ctx); err != nil {
		t.Fatal(err)
	}
	if err := connection.Write(ctx, websocket.MessageText, []byte("second")); err != nil {
		t.Fatal(err)
	}
	_, _, err := connection.Read(ctx)
	if status := websocket.CloseStatus(err); status != websocket.StatusTryAgainLater {
		t.Fatalf("expected rate-limit close, got status=%v err=%v", status, err)
	}
}

func protectedWebSocketTestServer(t *testing.T, rules *waf.CustomRuleSet, behavior func([]byte) []byte, mutations ...func(*config.Config)) (*httptest.Server, *httptest.Server) {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc; Path=/")
		w.Header().Set("Server", "secret-backend")
		w.Header().Set("X-Powered-By", "hidden-framework")
		connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		for {
			messageType, message, err := connection.Read(context.Background())
			if err != nil {
				return
			}
			if behavior != nil {
				message = behavior(message)
			}
			if err := connection.Write(context.Background(), messageType, message); err != nil {
				return
			}
		}
	}))
	t.Cleanup(backend.Close)

	cfg := config.Config{
		TargetURL:                     backend.URL,
		EnableSanitizer:               true,
		WAFMode:                       "block",
		EnableResponseInspection:      true,
		ResponseDiagnosticsErrorsOnly: true,
		EnableWebSocketProtection:     true,
		WebSocketMaxMessageSize:       1024 * 1024,
		WebSocketMessagesPerSecond:    100,
		WebSocketBurstLimit:           100,
		AllowedMethods:                []string{http.MethodGet},
		MaxConcurrentRequests:         20,
		MaxBodySize:                   1024 * 1024,
		MaxDecodedBodySize:            4 * 1024 * 1024,
	}
	for _, mutate := range mutations {
		mutate(&cfg)
	}
	httpProxy, err := BuildProxyWithRules(cfg, rules)
	if err != nil {
		t.Fatal(err)
	}
	webSocketProxy, err := BuildWebSocketProxy(cfg, rules)
	if err != nil {
		t.Fatal(err)
	}
	handler := MakeSecureHandlerWithProtection(
		httpProxy,
		webSocketProxy,
		ratelimit.NewManager(100, 100, 100, 20),
		blocklist.New(nil),
		cfg,
		rules,
	)
	front := httptest.NewServer(handler)
	t.Cleanup(front.Close)
	return front, backend
}

func dialWebSocketTestServer(t *testing.T, frontURL string, options *websocket.DialOptions) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, response, err := websocket.Dial(ctx, strings.Replace(frontURL, "http://", "ws://", 1), options)
	if err != nil {
		t.Fatalf("dial protected WebSocket: response=%v err=%v", response, err)
	}
	return connection
}
