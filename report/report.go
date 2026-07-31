// Package report turns structured Training Mode events into a self-contained
// HTML report. It relies on html/template contextual escaping so captured
// attack values remain inert text.
package report

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"dobotshield/traininglog"
)

// Report is the view model consumed by the HTML template.
type Report struct {
	CSS            template.CSS // embedded admin-config/styles/report.css
	GeneratedAt    string
	Source         string
	Total          int
	BlockedCount   int
	DetectedCount  int
	RequestCount   int
	ResponseCount  int
	WebSocketCount int
	UniqueIPs      int
	UniqueRules    int
	FirstSeen      string
	LastSeen       string
	Categories     []Stat
	TopIPs         []Stat
	Glossary       []GlossaryEntry
	Timeline       []EventView
}

// GlossaryEntry explains a category represented in the report.
type GlossaryEntry struct {
	Category      string
	CategoryClass string
	Count         int
	Title         string
	Summary       string
	Attack        string
	Defense       string
	Subtypes      []Subtype
}

// Stat is an aggregate category or IP count.
type Stat struct {
	Label   string
	Count   int
	Percent float64
}

// EventView is a rendered representation of one event.
type EventView struct {
	Index         int
	Timestamp     string
	RawTimestamp  string
	RequestID     string
	IP            string
	Method        string
	Path          string
	Phase         string
	Action        string
	Category      string
	Location      string
	Rule          string
	Payload       string
	Variants      []string
	CategoryClass string
	ActionClass   string
	FriendlyTitle string
	Attack        string
	Defense       string
}

// Build aggregates raw events into a renderable Report.
func Build(events []traininglog.Event, source string) Report {
	sorted := make([]traininglog.Event, len(events))
	copy(sorted, events)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Timestamp < sorted[j].Timestamp
	})

	report := Report{
		CSS:         loadReportCSS(),
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Source:      source,
		Total:       len(sorted),
	}

	categoryCounts := map[string]int{}
	ipCounts := map[string]int{}
	ruleSet := map[string]struct{}{}

	for i, ev := range sorted {
		switch ev.Action {
		case "blocked":
			report.BlockedCount++
		case "detected":
			report.DetectedCount++
		}
		switch ev.Phase {
		case "request":
			report.RequestCount++
		case "response":
			report.ResponseCount++
		case "websocket-client", "websocket-server":
			report.WebSocketCount++
		}

		category := orDash(ev.Category)
		categoryCounts[category]++
		if ev.IP != "" {
			ipCounts[ev.IP]++
		}
		if ev.Rule != "" {
			ruleSet[ev.Rule] = struct{}{}
		}

		info := lookupCategory(category)
		report.Timeline = append(report.Timeline, EventView{
			Index:         i + 1,
			Timestamp:     formatTimestamp(ev.Timestamp),
			RawTimestamp:  ev.Timestamp,
			RequestID:     ev.RequestID,
			IP:            orDash(ev.IP),
			Method:        ev.Method,
			Path:          ev.Path,
			Phase:         orDash(ev.Phase),
			Action:        orDash(ev.Action),
			Category:      category,
			Location:      ev.Location,
			Rule:          ev.Rule,
			Payload:       ev.Payload,
			Variants:      ev.Variants,
			CategoryClass: categoryClass(category),
			ActionClass:   actionClass(ev.Action),
			FriendlyTitle: info.Title,
			Attack:        info.Attack,
			Defense:       info.Defense,
		})
	}

	report.UniqueIPs = len(ipCounts)
	report.UniqueRules = len(ruleSet)
	report.Categories = topStats(categoryCounts, report.Total, 0)
	report.TopIPs = topStats(ipCounts, report.Total, 10)
	report.Glossary = buildGlossary(categoryCounts)

	if len(sorted) > 0 {
		report.FirstSeen = formatTimestamp(sorted[0].Timestamp)
		report.LastSeen = formatTimestamp(sorted[len(sorted)-1].Timestamp)
	}

	return report
}

// Generate writes the complete HTML report to w.
func Generate(events []traininglog.Event, source string, w io.Writer) error {
	report := Build(events, source)
	return reportTemplate.Execute(w, report)
}

// buildGlossary returns explanations ordered from most to least frequent.
func buildGlossary(categoryCounts map[string]int) []GlossaryEntry {
	entries := make([]GlossaryEntry, 0, len(categoryCounts))
	for category, count := range categoryCounts {
		if category == "" || category == "-" {
			continue
		}
		info := lookupCategory(category)
		entries = append(entries, GlossaryEntry{
			Category:      category,
			CategoryClass: categoryClass(category),
			Count:         count,
			Title:         info.Title,
			Summary:       info.Summary,
			Attack:        info.Attack,
			Defense:       info.Defense,
			Subtypes:      info.Subtypes,
		})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].Category < entries[j].Category
	})
	return entries
}

func topStats(counts map[string]int, total, limit int) []Stat {
	stats := make([]Stat, 0, len(counts))
	for label, count := range counts {
		percent := 0.0
		if total > 0 {
			percent = float64(count) * 100 / float64(total)
		}
		stats = append(stats, Stat{Label: label, Count: count, Percent: percent})
	}
	sort.SliceStable(stats, func(i, j int) bool {
		if stats[i].Count != stats[j].Count {
			return stats[i].Count > stats[j].Count
		}
		return stats[i].Label < stats[j].Label
	})
	if limit > 0 && len(stats) > limit {
		stats = stats[:limit]
	}
	return stats
}

func formatTimestamp(raw string) string {
	if raw == "" {
		return "-"
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC().Format("2006-01-02 15:04:05 UTC")
		}
	}
	return raw
}

func orDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

// categoryClass derives a stable color class from a category name.
func categoryClass(category string) string {
	var sum int
	for _, r := range category {
		sum += int(r)
	}
	return fmt.Sprintf("badge-%d", sum%8)
}

func actionClass(action string) string {
	if action == "blocked" {
		return "action-blocked"
	}
	return "action-detected"
}
