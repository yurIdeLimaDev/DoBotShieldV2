// Command report generates the DoBot Shield Training Mode HTML report from
// structured JSON Lines security events.
//
// Usage:
//
//	go run ./cmd/report                         # logs/training.jsonl -> training-report.html
//	go run ./cmd/report -in events.jsonl -out report.html
//	go run ./cmd/report -open                   # open the completed report
//
// This utility is separate from the WAF server. It opens no listening ports,
// requires no upstream application, and does not mutate proxy state.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"

	"dobotshield/report"
	"dobotshield/traininglog"
)

func main() {
	defaultIn := os.Getenv("TRAINING_LOG_FILE")
	if defaultIn == "" {
		defaultIn = filepath.Join("logs", "training.jsonl")
	}

	in := flag.String("in", defaultIn, "Training Mode JSON Lines event file")
	out := flag.String("out", "training-report.html", "output HTML file")
	open := flag.Bool("open", false, "open the report in a browser when complete")
	flag.Parse()

	if err := run(*in, *out, *open); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(in, out string, open bool) error {
	events, err := traininglog.Load(in)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("training event file not found at %q; start the WAF with TRAINING_MODE=true and generate representative traffic first", in)
		}
		return fmt.Errorf("read %q: %w", in, err)
	}

	file, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %q: %w", out, err)
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict permissions on %q: %w", out, err)
	}

	if err := report.Generate(events, in, file); err != nil {
		return fmt.Errorf("generate report: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("finalize %q: %w", out, err)
	}

	abs, _ := filepath.Abs(out)
	printSummary(events, abs)

	if open {
		if err := openInBrowser(abs); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not open the browser: %v\n", err)
		}
	}
	return nil
}

func printSummary(events []traininglog.Event, outPath string) {
	categories := map[string]int{}
	blocked, detected := 0, 0
	for _, ev := range events {
		categories[ev.Category]++
		switch ev.Action {
		case "blocked":
			blocked++
		case "detected":
			detected++
		}
	}

	fmt.Println("Generated the Training Mode report.")
	fmt.Printf("  Events:      %d (%d blocked, %d detected)\n", len(events), blocked, detected)
	fmt.Printf("  Categories:  %s\n", formatCategories(categories))
	fmt.Printf("  File:        %s\n", outPath)
}

func formatCategories(categories map[string]int) string {
	if len(categories) == 0 {
		return "(none)"
	}
	type kv struct {
		name  string
		count int
	}
	pairs := make([]kv, 0, len(categories))
	for name, count := range categories {
		pairs = append(pairs, kv{name, count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].name < pairs[j].name
	})

	out := ""
	for i, p := range pairs {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s=%d", p.name, p.count)
	}
	return out
}

func openInBrowser(path string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", path).Start()
	case "darwin":
		return exec.Command("open", path).Start()
	default:
		return exec.Command("xdg-open", path).Start()
	}
}
