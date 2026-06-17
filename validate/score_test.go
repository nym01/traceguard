package main

import (
	"os"
	"testing"
	"time"
)

func writeTempLog(t *testing.T, lines []string) string {
	t.Helper()
	f, err := os.CreateTemp("", "validate-test-*.log")
	if err != nil {
		t.Fatalf("creating temp log: %v", err)
	}
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatalf("writing temp log: %v", err)
		}
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func TestLoadAlerts_SkipsNonAlertAndMalformedLines(t *testing.T) {
	path := writeTempLog(t, []string{
		`{"type":"exec","timestamp":"2026-06-17T10:00:00Z","comm":"ls"}`,
		`not even json`,
		`{"type":"alert","timestamp":"2026-06-17T10:00:01Z","rule":"sensitive-file-access"}`,
		``,
	})
	alerts, err := loadAlerts(path)
	if err != nil {
		t.Fatalf("loadAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected exactly 1 alert, got %d: %+v", len(alerts), alerts)
	}
	if alerts[0].Rule != "sensitive-file-access" {
		t.Errorf("expected sensitive-file-access, got %q", alerts[0].Rule)
	}
}

func TestScoreTestResult_AttackFiresCorrectRule_Passes(t *testing.T) {
	t0 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	alerts := []alertLogEntry{
		{Type: "alert", Timestamp: t0.Add(2 * time.Second), Rule: "sensitive-file-access"},
	}
	tr := &TestResult{
		TestCase: TestCase{Name: "read-shadow", Category: "attack", ExpectRule: "sensitive-file-access"},
		Started:  t0,
		Ended:    t0.Add(5 * time.Second),
	}
	scoreTestResult(tr, alerts)
	if !tr.Passed {
		t.Errorf("expected test to pass, AlertsSeen=%v", tr.AlertsSeen)
	}
}

func TestScoreTestResult_AttackFiresWrongRule_Fails(t *testing.T) {
	t0 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	alerts := []alertLogEntry{
		{Type: "alert", Timestamp: t0.Add(2 * time.Second), Rule: "readonly-write"},
	}
	tr := &TestResult{
		TestCase: TestCase{Name: "read-shadow", Category: "attack", ExpectRule: "sensitive-file-access"},
		Started:  t0,
		Ended:    t0.Add(5 * time.Second),
	}
	scoreTestResult(tr, alerts)
	if tr.Passed {
		t.Errorf("expected test to fail since the expected rule never fired, got Passed=true")
	}
}

func TestScoreTestResult_AttackNoAlertAtAll_Fails(t *testing.T) {
	t0 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	tr := &TestResult{
		TestCase: TestCase{Name: "read-shadow", Category: "attack", ExpectRule: "sensitive-file-access"},
		Started:  t0,
		Ended:    t0.Add(5 * time.Second),
	}
	scoreTestResult(tr, nil)
	if tr.Passed {
		t.Errorf("expected test to fail with zero alerts, got Passed=true")
	}
}

func TestScoreTestResult_BenignWithNoAlerts_Passes(t *testing.T) {
	t0 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	tr := &TestResult{
		TestCase: TestCase{Name: "ls-home", Category: "benign"},
		Started:  t0,
		Ended:    t0.Add(5 * time.Second),
	}
	scoreTestResult(tr, nil)
	if !tr.Passed {
		t.Errorf("expected benign test with no alerts to pass")
	}
}

func TestScoreTestResult_BenignWithUnexpectedAlert_Fails(t *testing.T) {
	t0 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	alerts := []alertLogEntry{
		{Type: "alert", Timestamp: t0.Add(1 * time.Second), Rule: "anomalous-outbound-connection"},
	}
	tr := &TestResult{
		TestCase: TestCase{Name: "curl-example", Category: "benign"},
		Started:  t0,
		Ended:    t0.Add(5 * time.Second),
	}
	scoreTestResult(tr, alerts)
	if tr.Passed {
		t.Errorf("expected benign test to fail (false positive) since an alert fired in its window")
	}
}

func TestScoreTestResult_IgnoresAlertsOutsideWindow(t *testing.T) {
	t0 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	alerts := []alertLogEntry{
		{Type: "alert", Timestamp: t0.Add(-10 * time.Second), Rule: "unexpected-shell-spawn"},
		{Type: "alert", Timestamp: t0.Add(10 * time.Second), Rule: "unexpected-shell-spawn"},
	}
	tr := &TestResult{
		TestCase: TestCase{Name: "ls-home", Category: "benign"},
		Started:  t0,
		Ended:    t0.Add(5 * time.Second),
	}
	scoreTestResult(tr, alerts)
	if !tr.Passed {
		t.Errorf("expected benign test to pass since both alerts fall outside its window, got AlertsSeen=%v", tr.AlertsSeen)
	}
}

func TestBuildReport_ComputesRatesCorrectly(t *testing.T) {
	results := []TestResult{
		{TestCase: TestCase{Category: "attack"}, Passed: true},
		{TestCase: TestCase{Category: "attack"}, Passed: true},
		{TestCase: TestCase{Category: "attack"}, Passed: false},
		{TestCase: TestCase{Category: "attack"}, Passed: true},
		{TestCase: TestCase{Category: "benign"}, Passed: true},
		{TestCase: TestCase{Category: "benign"}, Passed: true},
		{TestCase: TestCase{Category: "benign"}, Passed: false},
	}
	rep := buildReport(results)
	if got := rep.DetectionRate; got < 74.9 || got > 75.1 {
		t.Errorf("expected detection rate ~75.0%%, got %.2f%%", got)
	}
	if got := rep.FalsePositiveRate; got < 33.2 || got > 33.4 {
		t.Errorf("expected false positive rate ~33.3%%, got %.2f%%", got)
	}
}

func TestBuildReport_NoAttacksOrBenign_NoDivideByZero(t *testing.T) {
	rep := buildReport(nil)
	if rep.DetectionRate != 0 || rep.FalsePositiveRate != 0 {
		t.Errorf("expected zero rates with no results, got detection=%.2f fp=%.2f", rep.DetectionRate, rep.FalsePositiveRate)
	}
}
