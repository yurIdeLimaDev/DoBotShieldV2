package report

import (
	"bytes"
	"strings"
	"testing"

	"dobotshield/traininglog"
)

func sampleEvents() []traininglog.Event {
	return []traininglog.Event{
		{
			Timestamp: "2026-06-02T10:05:00Z",
			IP:        "203.0.113.11",
			Method:    "POST",
			Path:      "/items",
			Phase:     "request",
			Action:    "blocked",
			Category:  "SQLi",
			Location:  "Body",
			Rule:      "union select",
			Payload:   "id=1 UNION SELECT password",
			Variants:  []string{"id=1 UNION SELECT password"},
		},
		{
			Timestamp: "2026-06-02T10:00:00Z",
			IP:        "203.0.113.10",
			Method:    "GET",
			Path:      "/search",
			Phase:     "request",
			Action:    "blocked",
			Category:  "XSS",
			Location:  "Query",
			Rule:      "(?i)<\\s*script",
			Payload:   "q=<script>alert(1)</script>",
			Variants:  []string{"q=<script>alert(1)</script>", "q=<script>alert(1)</script>"},
		},
		{
			Timestamp: "2026-06-02T10:10:00Z",
			IP:        "203.0.113.10",
			Path:      "/profile",
			Phase:     "response",
			Action:    "detected",
			Category:  "RESPONSE_SQL_ERROR",
			Location:  "Response Body",
			Rule:      "SQLSTATE",
			Payload:   "SQLSTATE[42000]",
		},
	}
}

func TestBuildAggregates(t *testing.T) {
	report := Build(sampleEvents(), "logs/training.jsonl")

	if report.Total != 3 {
		t.Fatalf("expected total 3, got %d", report.Total)
	}
	if report.BlockedCount != 2 || report.DetectedCount != 1 {
		t.Fatalf("unexpected action counts: %d blocked, %d detected", report.BlockedCount, report.DetectedCount)
	}
	if report.RequestCount != 2 || report.ResponseCount != 1 {
		t.Fatalf("unexpected phase counts: %d req, %d resp", report.RequestCount, report.ResponseCount)
	}
	if report.UniqueIPs != 2 {
		t.Fatalf("expected 2 unique IPs, got %d", report.UniqueIPs)
	}
	// The timeline must be sorted by ascending timestamp.
	if report.Timeline[0].Category != "XSS" {
		t.Fatalf("expected earliest event (XSS) first, got %q", report.Timeline[0].Category)
	}
	if report.Timeline[2].Category != "RESPONSE_SQL_ERROR" {
		t.Fatalf("expected latest event last, got %q", report.Timeline[2].Category)
	}
	if report.FirstSeen == "" || report.LastSeen == "" {
		t.Fatalf("expected first/last seen to be set")
	}
}

func TestBuildCountsWebSocketPhases(t *testing.T) {
	events := []traininglog.Event{
		{Timestamp: "2026-06-02T10:00:00Z", Phase: "websocket-client", Action: "blocked", Category: "XSS"},
		{Timestamp: "2026-06-02T10:00:01Z", Phase: "websocket-server", Action: "detected", Category: "CUSTOM_RULE_leak"},
	}
	report := Build(events, "")
	if report.WebSocketCount != 2 || report.RequestCount != 0 || report.ResponseCount != 0 {
		t.Fatalf("unexpected phase counts: websocket=%d request=%d response=%d", report.WebSocketCount, report.RequestCount, report.ResponseCount)
	}
	if got := lookupCategory("CUSTOM_RULE_leak").Title; got != "Operator-defined policy match" {
		t.Fatalf("unexpected custom-rule glossary title: %q", got)
	}
}

func TestGenerateEscapesPayload(t *testing.T) {
	var buf bytes.Buffer
	if err := Generate(sampleEvents(), "logs/training.jsonl", &buf); err != nil {
		t.Fatalf("generate: %v", err)
	}
	html := buf.String()

	// The XSS payload must never appear as an executable tag in the report.
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatalf("payload was not escaped; the report is vulnerable to stored XSS")
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("expected escaped payload in the report")
	}
	if !strings.Contains(html, "Training Mode") {
		t.Fatalf("expected report title")
	}
	if !strings.Contains(html, "SQLi") || !strings.Contains(html, "XSS") {
		t.Fatalf("expected categories rendered")
	}
}

func TestGenerateEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Generate(nil, "", &buf); err != nil {
		t.Fatalf("generate empty: %v", err)
	}
	if !strings.Contains(buf.String(), "No events recorded") {
		t.Fatalf("expected empty-state message")
	}
}

func TestGlossaryCoversRequestedCategories(t *testing.T) {
	requested := []string{
		"SQLi", "CMD_INJ", "JNDI", "NoSQLi", "OPEN_REDIRECT",
		"PATH_TRAVERSAL", "RESPONSE_SQL_ERROR", "RESPONSE_XSS_PATTERN", "SSRF", "SSTI", "XSS",
	}
	for _, category := range requested {
		info := lookupCategory(category)
		if info.Title == defaultCategoryInfo.Title {
			t.Fatalf("category %q falls back to the default title without a dedicated explanation", category)
		}
		if len(info.Attack) < 40 || len(info.Defense) < 30 {
			t.Fatalf("category %q explanation is too short: attack=%d defense=%d", category, len(info.Attack), len(info.Defense))
		}
		if info.Summary == "" {
			t.Fatalf("category %q has no summary", category)
		}
		if len(info.Subtypes) == 0 {
			t.Fatalf("category %q has no subtypes", category)
		}
		for _, subtype := range info.Subtypes {
			if subtype.Name == "" || subtype.Explanation == "" {
				t.Fatalf("category %q has an incomplete subtype: %+v", category, subtype)
			}
			if subtype.Example != "" && subtype.Reading == "" {
				t.Fatalf("category %q subtype %q has an example without an explanation", category, subtype.Name)
			}
		}
	}
}

func TestLookupUnknownCategoryFallsBack(t *testing.T) {
	info := lookupCategory("UNKNOWN_CATEGORY")
	if info.Attack == "" || info.Defense == "" {
		t.Fatalf("expected generic explanation for unknown category")
	}
	if info.Title != "UNKNOWN_CATEGORY" {
		t.Fatalf("expected unknown category to keep its name as title, got %q", info.Title)
	}
}

func TestBuildPopulatesGlossaryAndEvents(t *testing.T) {
	report := Build(sampleEvents(), "logs/training.jsonl")

	if len(report.Glossary) != 3 {
		t.Fatalf("expected 3 glossary entries (XSS, SQLi, RESPONSE_SQL_ERROR), got %d", len(report.Glossary))
	}
	// Entries must be sorted by descending count.
	for i := 1; i < len(report.Glossary); i++ {
		if report.Glossary[i-1].Count < report.Glossary[i].Count {
			t.Fatalf("glossary is not sorted by descending count: %+v", report.Glossary)
		}
	}
	for _, entry := range report.Glossary {
		if entry.Attack == "" || entry.Defense == "" {
			t.Fatalf("glossary entry %q missing explanation", entry.Category)
		}
	}
	// Every event must include its explanation.
	for _, event := range report.Timeline {
		if event.Attack == "" || event.Defense == "" {
			t.Fatalf("event %q (category %q) missing explanation", event.Path, event.Category)
		}
	}
}

func TestGenerateIncludesExplanations(t *testing.T) {
	var buf bytes.Buffer
	if err := Generate(sampleEvents(), "logs/training.jsonl", &buf); err != nil {
		t.Fatalf("generate: %v", err)
	}
	html := buf.String()

	for _, needle := range []string{
		"Understand the detected categories",
		"What it means",
		"Common forms",
		"Interpretation:",
		"DoBot Shield response",
		"SQL Injection",
		"Cross-Site Scripting",
		"What was detected and how did DoBot Shield respond?",
	} {
		if !strings.Contains(html, needle) {
			t.Fatalf("expected report to contain %q", needle)
		}
	}
}

func TestNoEmDashInExplanations(t *testing.T) {
	for category, info := range categoryGlossary {
		texts := []string{info.Summary, info.Attack, info.Defense}
		for _, subtype := range info.Subtypes {
			texts = append(texts, subtype.Name, subtype.Explanation, subtype.Reading)
		}
		for _, value := range texts {
			if strings.ContainsRune(value, '\u2014') || strings.ContainsRune(value, '\u2013') {
				t.Fatalf("category %q contains a dash in: %q", category, value)
			}
		}
	}
}

func TestCategoryClassStable(t *testing.T) {
	if !strings.HasPrefix(categoryClass("SQLi"), "badge-") {
		t.Fatalf("unexpected class format")
	}
}
