package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

const (
	maxCustomRulesFileBytes = 1024 * 1024
	maxCustomRules          = 256
	maxCustomPatternBytes   = 4096
)

var customRuleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// CustomRulesFile is the strict, versioned JSON format accepted from operators.
// Unknown fields are rejected so spelling mistakes cannot silently weaken policy.
type CustomRulesFile struct {
	Version int                `json:"version"`
	Rules   []CustomRuleConfig `json:"rules"`
}

// CustomRuleConfig describes one operator-defined RE2 regular expression.
type CustomRuleConfig struct {
	ID          string `json:"id"`
	Phase       string `json:"phase"`
	Target      string `json:"target"`
	Pattern     string `json:"pattern"`
	Description string `json:"description,omitempty"`
}

type customRule struct {
	id          string
	phase       string
	target      string
	description string
	pattern     *regexp.Regexp
}

// CustomRuleSet is immutable after loading and safe for concurrent use.
type CustomRuleSet struct {
	rules []customRule
}

// LoadCustomRules loads and validates an operator rule file. An empty path
// disables custom rules. Go's regexp engine implements RE2 semantics and does
// not permit exponential-time backtracking.
func LoadCustomRules(path string) (*CustomRuleSet, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return &CustomRuleSet{}, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open custom rules: %w", err)
	}
	defer file.Close()

	payload, err := io.ReadAll(io.LimitReader(file, maxCustomRulesFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read custom rules: %w", err)
	}
	if len(payload) > maxCustomRulesFileBytes {
		return nil, fmt.Errorf("custom rules file exceeds %d bytes", maxCustomRulesFileBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document CustomRulesFile
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode custom rules: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return nil, err
	}
	return CompileCustomRules(document)
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("custom rules file contains trailing JSON data")
		}
		return fmt.Errorf("decode trailing custom rules data: %w", err)
	}
	return nil
}

// CompileCustomRules validates an in-memory rule document. It is exported for
// embedders and tests that do not load configuration from disk.
func CompileCustomRules(document CustomRulesFile) (*CustomRuleSet, error) {
	if document.Version != 1 {
		return nil, fmt.Errorf("custom rules version must be 1")
	}
	if len(document.Rules) > maxCustomRules {
		return nil, fmt.Errorf("custom rules file contains %d rules; maximum is %d", len(document.Rules), maxCustomRules)
	}

	set := &CustomRuleSet{rules: make([]customRule, 0, len(document.Rules))}
	seen := make(map[string]struct{}, len(document.Rules))
	for index, candidate := range document.Rules {
		id := strings.TrimSpace(candidate.ID)
		phase := strings.ToLower(strings.TrimSpace(candidate.Phase))
		target := strings.ToLower(strings.TrimSpace(candidate.Target))
		patternText := candidate.Pattern

		if !customRuleIDPattern.MatchString(id) {
			return nil, fmt.Errorf("custom rule %d has an invalid id", index+1)
		}
		key := strings.ToLower(id)
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("custom rule id %q is duplicated", id)
		}
		seen[key] = struct{}{}
		if !validCustomRuleTarget(phase, target) {
			return nil, fmt.Errorf("custom rule %q has invalid phase/target combination %q/%q", id, phase, target)
		}
		if patternText == "" || len(patternText) > maxCustomPatternBytes {
			return nil, fmt.Errorf("custom rule %q pattern must contain 1 to %d bytes", id, maxCustomPatternBytes)
		}
		compiled, err := regexp.Compile(patternText)
		if err != nil {
			return nil, fmt.Errorf("compile custom rule %q: %w", id, err)
		}

		set.rules = append(set.rules, customRule{
			id:          id,
			phase:       phase,
			target:      target,
			description: strings.TrimSpace(candidate.Description),
			pattern:     compiled,
		})
	}
	return set, nil
}

func validCustomRuleTarget(phase, target string) bool {
	switch phase {
	case "request":
		switch target {
		case "any", "path", "query", "host", "headers", "body":
			return true
		}
	case "response":
		switch target {
		case "any", "headers", "body":
			return true
		}
	case "websocket-client", "websocket-server":
		return target == "any" || target == "message"
	}
	return false
}

// Len returns the number of compiled custom rules.
func (set *CustomRuleSet) Len() int {
	if set == nil {
		return 0
	}
	return len(set.rules)
}

// CheckRequest evaluates request-phase rules and returns the stable custom
// rule identifier rather than the operator's expression, keeping logs concise.
func (set *CustomRuleSet) CheckRequest(r *http.Request, body []byte) (bool, string, string) {
	if set == nil || r == nil {
		return false, "", ""
	}
	for _, rule := range set.rules {
		if rule.phase != "request" {
			continue
		}
		for _, candidate := range customRequestCandidates(r, body, rule.target) {
			if customRuleMatches(rule, candidate.value) {
				return true, "CUSTOM_RULE_" + rule.id + " in " + candidate.location, "custom:" + rule.id
			}
		}
	}
	return false, "", ""
}

// CheckResponse evaluates response-phase custom rules.
func (set *CustomRuleSet) CheckResponse(resp *http.Response, body []byte) (bool, string, string) {
	if malicious, details, rule := set.CheckResponseHeaders(resp); malicious {
		return true, details, rule
	}
	return set.CheckResponseBody(body)
}

// CheckResponseHeaders evaluates only response headers. It is separate from
// body inspection so headers remain protected on HEAD, attachment, and empty
// responses without evaluating them twice on ordinary responses.
func (set *CustomRuleSet) CheckResponseHeaders(resp *http.Response) (bool, string, string) {
	if set == nil {
		return false, "", ""
	}
	for _, rule := range set.rules {
		if rule.phase != "response" || (rule.target != "any" && rule.target != "headers") {
			continue
		}
		for _, candidate := range customResponseCandidates(resp, nil, "headers") {
			if customRuleMatches(rule, candidate.value) {
				return true, "CUSTOM_RULE_" + rule.id + " in " + candidate.location, "custom:" + rule.id
			}
		}
	}
	return false, "", ""
}

// CheckResponseBody evaluates only the bounded response body prefix.
func (set *CustomRuleSet) CheckResponseBody(body []byte) (bool, string, string) {
	if set == nil || len(body) == 0 {
		return false, "", ""
	}
	for _, rule := range set.rules {
		if rule.phase != "response" || (rule.target != "any" && rule.target != "body") {
			continue
		}
		if customRuleMatches(rule, string(body)) {
			return true, "CUSTOM_RULE_" + rule.id + " in Response Body", "custom:" + rule.id
		}
	}
	return false, "", ""
}

// CheckMessage evaluates one fully reconstructed WebSocket message.
func (set *CustomRuleSet) CheckMessage(phase string, message []byte) (bool, string, string) {
	if set == nil {
		return false, "", ""
	}
	phase = strings.ToLower(strings.TrimSpace(phase))
	if phase != "websocket-client" && phase != "websocket-server" {
		return false, "", ""
	}
	for _, rule := range set.rules {
		if rule.phase == phase && customRuleMatches(rule, string(message)) {
			return true, "CUSTOM_RULE_" + rule.id + " in WebSocket Message", "custom:" + rule.id
		}
	}
	return false, "", ""
}

type customCandidate struct {
	location string
	value    string
}

func customRequestCandidates(r *http.Request, body []byte, target string) []customCandidate {
	var candidates []customCandidate
	add := func(targetName, location, value string) {
		if (target == "any" || target == targetName) && value != "" {
			candidates = append(candidates, customCandidate{location: location, value: value})
		}
	}

	add("path", "Path", r.URL.EscapedPath())
	add("query", "Query", r.URL.RawQuery)
	add("host", "Host", r.Host)
	if target == "any" || target == "headers" {
		for name, values := range r.Header {
			for _, value := range values {
				add("headers", "Header "+name, value)
			}
		}
	}
	add("body", "Body", string(body))
	return candidates
}

func customResponseCandidates(resp *http.Response, body []byte, target string) []customCandidate {
	var candidates []customCandidate
	if (target == "any" || target == "headers") && resp != nil {
		for name, values := range resp.Header {
			for _, value := range values {
				if value != "" {
					candidates = append(candidates, customCandidate{location: "Response Header " + name, value: value})
				}
			}
		}
	}
	if (target == "any" || target == "body") && len(body) > 0 {
		candidates = append(candidates, customCandidate{location: "Response Body", value: string(body)})
	}
	return candidates
}

func customRuleMatches(rule customRule, value string) bool {
	for _, variant := range buildInspectionVariants(value) {
		if rule.pattern.MatchString(variant) {
			return true
		}
	}
	return false
}
