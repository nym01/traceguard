package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// alertLogEntry mirrors the subset of fields we need from each JSON line
// in traceguard's log file. Lines that aren't alerts (raw verbose events,
// if -verbose was used) or that fail to parse are simply skipped.
type alertLogEntry struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Rule      string    `json:"rule"`
}

// loadAlerts reads every alert-type line from a traceguard log file.
func loadAlerts(path string) ([]alertLogEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var alerts []alertLogEntry
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		var e alertLogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			continue // skip malformed/non-JSON lines
		}
		if e.Type != "alert" {
			continue // skip raw verbose events etc.
		}
		alerts = append(alerts, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return alerts, nil
}

type TestCase struct {
	Name       string
	Category   string   // "attack" or "benign"
	ExpectRule string   // rule expected to fire; empty for benign cases
	Cmd        []string // command (argv) the validator runs to exercise this case
}

type TestResult struct {
	TestCase
	Started    time.Time
	Ended      time.Time
	AlertsSeen []string
	Passed     bool
}

// scoreTestResult fills in AlertsSeen and Passed for one test, given the
// full set of alerts loaded from the log. An alert "belongs" to a test if
// its timestamp falls within that test's [Started, Ended] window.
func scoreTestResult(tr *TestResult, allAlerts []alertLogEntry) {
	tr.AlertsSeen = nil
	for _, a := range allAlerts {
		if a.Timestamp.Before(tr.Started) || a.Timestamp.After(tr.Ended) {
			continue
		}
		tr.AlertsSeen = append(tr.AlertsSeen, a.Rule)
	}

	switch tr.Category {
	case "attack":
		tr.Passed = false
		for _, r := range tr.AlertsSeen {
			if r == tr.ExpectRule {
				tr.Passed = true
				break
			}
		}
	case "benign":
		tr.Passed = len(tr.AlertsSeen) == 0
	}
}

type Report struct {
	Results           []TestResult
	DetectionRate     float64 // passed attacks / total attacks, as a percentage
	FalsePositiveRate float64 // failed benign / total benign, as a percentage
}

func buildReport(results []TestResult) Report {
	var attacksTotal, attacksPassed, benignTotal, benignFailed int
	for _, r := range results {
		switch r.Category {
		case "attack":
			attacksTotal++
			if r.Passed {
				attacksPassed++
			}
		case "benign":
			benignTotal++
			if !r.Passed {
				benignFailed++
			}
		}
	}
	rep := Report{Results: results}
	if attacksTotal > 0 {
		rep.DetectionRate = float64(attacksPassed) / float64(attacksTotal) * 100
	}
	if benignTotal > 0 {
		rep.FalsePositiveRate = float64(benignFailed) / float64(benignTotal) * 100
	}
	return rep
}

func (rep Report) String() string {
	var b strings.Builder
	b.WriteString("TraceGuard Detection Validation Report\n")
	b.WriteString("=======================================\n\n")
	for _, r := range rep.Results {
		status := "FAIL"
		if r.Passed {
			status = "PASS"
		}
		expect := r.ExpectRule
		if expect == "" {
			expect = "(none)"
		}
		b.WriteString(fmt.Sprintf("[%s] %-32s category=%-7s expected=%-28s seen=%v\n",
			status, r.Name, r.Category, expect, r.AlertsSeen))
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("Detection rate:      %.1f%%\n", rep.DetectionRate))
	b.WriteString(fmt.Sprintf("False positive rate: %.1f%%\n", rep.FalsePositiveRate))
	return b.String()
}
