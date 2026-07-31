package waf

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCustomRulesInspectEverySupportedPhase(t *testing.T) {
	set, err := CompileCustomRules(CustomRulesFile{
		Version: 1,
		Rules: []CustomRuleConfig{
			{ID: "tenant-path", Phase: "request", Target: "path", Pattern: `(?i)/private-area`},
			{ID: "response-secret", Phase: "response", Target: "body", Pattern: `INTERNAL_[A-Z0-9]{8}`},
			{ID: "ws-command", Phase: "websocket-client", Target: "message", Pattern: `(?i)admin:\s*shutdown`},
			{ID: "ws-leak", Phase: "websocket-server", Target: "message", Pattern: `secret-token-[0-9]+`},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	request := &http.Request{URL: &url.URL{Path: "/private-area"}, Header: make(http.Header)}
	if malicious, details, rule := set.CheckRequest(request, nil); !malicious || details != "CUSTOM_RULE_tenant-path in Path" || rule != "custom:tenant-path" {
		t.Fatalf("unexpected request decision: malicious=%v details=%q rule=%q", malicious, details, rule)
	}
	if malicious, _, _ := set.CheckResponse(&http.Response{Header: make(http.Header)}, []byte("INTERNAL_ABC12345")); !malicious {
		t.Fatal("expected response custom rule to match")
	}
	if malicious, _, _ := set.CheckMessage("websocket-client", []byte("admin: shutdown")); !malicious {
		t.Fatal("expected client WebSocket custom rule to match")
	}
	if malicious, _, _ := set.CheckMessage("websocket-server", []byte("secret-token-42")); !malicious {
		t.Fatal("expected server WebSocket custom rule to match")
	}
}

func TestCustomRulesUseWAFNormalization(t *testing.T) {
	set, err := CompileCustomRules(CustomRulesFile{
		Version: 1,
		Rules:   []CustomRuleConfig{{ID: "normalized", Phase: "request", Target: "query", Pattern: `(?i)<script`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{URL: &url.URL{RawQuery: "q=%253Cscript%253E"}, Header: make(http.Header)}
	if malicious, _, _ := set.CheckRequest(request, nil); !malicious {
		t.Fatal("expected the custom rule to match a repeatedly encoded variant")
	}
}

func TestLoadCustomRulesRejectsUnsafeDocuments(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{name: "unknown field", json: `{"version":1,"rules":[],"typo":true}`},
		{name: "wrong version", json: `{"version":2,"rules":[]}`},
		{name: "duplicate id", json: `{"version":1,"rules":[{"id":"same","phase":"request","target":"body","pattern":"a"},{"id":"SAME","phase":"request","target":"body","pattern":"b"}]}`},
		{name: "invalid regex", json: `{"version":1,"rules":[{"id":"bad","phase":"request","target":"body","pattern":"("}]}`},
		{name: "invalid phase target", json: `{"version":1,"rules":[{"id":"bad","phase":"response","target":"query","pattern":"a"}]}`},
		{name: "trailing document", json: `{"version":1,"rules":[]} {"version":1,"rules":[]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.json")
			if err := os.WriteFile(path, []byte(test.json), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadCustomRules(path); err == nil {
				t.Fatal("expected invalid custom rules to be rejected")
			}
		})
	}
}

func TestLoadCustomRulesEnforcesFileAndPatternBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	oversized := strings.Repeat("x", maxCustomRulesFileBytes+1)
	if err := os.WriteFile(path, []byte(oversized), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCustomRules(path); err == nil {
		t.Fatal("expected oversized file to be rejected")
	}

	_, err := CompileCustomRules(CustomRulesFile{
		Version: 1,
		Rules:   []CustomRuleConfig{{ID: "large", Phase: "request", Target: "body", Pattern: strings.Repeat("a", maxCustomPatternBytes+1)}},
	})
	if err == nil {
		t.Fatal("expected oversized pattern to be rejected")
	}
}

func TestEmptyCustomRulesPathDisablesRules(t *testing.T) {
	set, err := LoadCustomRules(" ")
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 0 {
		t.Fatalf("expected zero rules, got %d", set.Len())
	}
}
