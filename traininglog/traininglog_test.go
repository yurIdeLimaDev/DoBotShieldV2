package traininglog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	defer file.Close()
	if _, err := file.WriteString(line + "\n"); err != nil {
		t.Fatalf("append line: %v", err)
	}
}

func TestLoggerRecordAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "training.jsonl")
	logger := New(path)
	if !logger.Enabled() {
		t.Fatalf("expected logger to be enabled")
	}

	logger.Record(Event{
		Timestamp: "2026-06-02T10:00:00Z",
		IP:        "203.0.113.10",
		Phase:     "request",
		Action:    "blocked",
		Category:  "XSS",
		Location:  "Query",
		Rule:      "(?i)<\\s*script",
		Payload:   "q=<script>alert(1)</script>",
		Variants:  []string{"q=<script>alert(1)</script>"},
	})
	logger.Record(Event{
		Timestamp: "2026-06-02T10:01:00Z",
		IP:        "203.0.113.11",
		Phase:     "request",
		Action:    "detected",
		Category:  "SQLi",
		Rule:      "union select",
		Payload:   "id=1 UNION SELECT 1",
	})
	if err := logger.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	events, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Category != "XSS" || events[0].Location != "Query" {
		t.Fatalf("unexpected first event: %+v", events[0])
	}
	if events[1].Category != "SQLi" || events[1].Action != "detected" {
		t.Fatalf("unexpected second event: %+v", events[1])
	}
}

func TestLoggerAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "training.jsonl")

	first := New(path)
	first.Record(Event{Timestamp: "t1", Category: "XSS"})
	if err := first.Close(); err != nil {
		t.Fatalf("close first: %v", err)
	}

	second := New(path)
	second.Record(Event{Timestamp: "t2", Category: "SQLi"})
	if err := second.Close(); err != nil {
		t.Fatalf("close second: %v", err)
	}

	events, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected appended file to have 2 events, got %d", len(events))
	}
}

func TestSanitizeTruncatesLongFields(t *testing.T) {
	long := strings.Repeat("A", maxPayloadBytes+500)
	manyVariants := make([]string, maxVariants+5)
	for i := range manyVariants {
		manyVariants[i] = strings.Repeat("B", maxVariantBytes+10)
	}

	ev := sanitize(Event{
		Payload:  long,
		Rule:     strings.Repeat("C", maxRuleBytes+10),
		Variants: manyVariants,
	})

	if len(ev.Payload) > maxPayloadBytes+len(truncationMark) {
		t.Fatalf("payload not truncated: len=%d", len(ev.Payload))
	}
	if !strings.HasSuffix(ev.Payload, truncationMark) {
		t.Fatalf("expected truncation mark on payload")
	}
	if len(ev.Variants) != maxVariants {
		t.Fatalf("expected variants capped at %d, got %d", maxVariants, len(ev.Variants))
	}
	for _, v := range ev.Variants {
		if len(v) > maxVariantBytes+len(truncationMark) {
			t.Fatalf("variant not truncated: len=%d", len(v))
		}
	}
}

func TestSanitizeDoesNotMutateCaller(t *testing.T) {
	original := []string{strings.Repeat("X", maxVariantBytes+50)}
	_ = sanitize(Event{Variants: original})
	if len(original[0]) != maxVariantBytes+50 {
		t.Fatalf("sanitize mutated caller's slice")
	}
}

func TestDisabledLoggerIsNoop(t *testing.T) {
	var logger *Logger
	if logger.Enabled() {
		t.Fatalf("nil logger should not be enabled")
	}
	logger.Record(Event{Category: "XSS"}) // must not panic

	degraded := New("")
	if degraded.Enabled() {
		t.Fatalf("logger with empty path should be degraded")
	}
	degraded.Record(Event{Category: "XSS"}) // must not panic either
}

func TestGlobalConfigureAndRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "global.jsonl")

	Configure(true, path)
	t.Cleanup(func() { _ = CloseDefault() })

	if !Enabled() {
		t.Fatalf("expected global logger to be enabled")
	}
	Record(Event{Timestamp: "t1", Category: "CMD_INJ", Rule: ";id"})

	if err := CloseDefault(); err != nil {
		t.Fatalf("close default: %v", err)
	}
	if Enabled() {
		t.Fatalf("expected global logger to be disabled after close")
	}

	events, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(events) != 1 || events[0].Category != "CMD_INJ" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestConfigureDisabled(t *testing.T) {
	Configure(false, filepath.Join(t.TempDir(), "off.jsonl"))
	t.Cleanup(func() { _ = CloseDefault() })
	if Enabled() {
		t.Fatalf("expected disabled global logger")
	}
	Record(Event{Category: "XSS"}) // no-op, no panic
}

func TestLoadSkipsCorruptLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed.jsonl")
	logger := New(path)
	logger.Record(Event{Timestamp: "t1", Category: "XSS"})
	logger.Close()

	// Append one invalid line and one valid line manually.
	appendLine(t, path, "this is not json")
	appendLine(t, path, `{"timestamp":"t2","category":"SQLi","ip":"1.2.3.4","phase":"request","action":"blocked","rule":"r","payload":"p"}`)

	events, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 valid events ignoring corrupt line, got %d", len(events))
	}
}
