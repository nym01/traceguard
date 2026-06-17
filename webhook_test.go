package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestWebhookSender_SendsCorrectPayload(t *testing.T) {
	var mu sync.Mutex
	var received webhookPayload
	gotReq := make(chan struct{}, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("server: failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		gotReq <- struct{}{}
	}))
	defer srv.Close()

	ch := make(chan Alert, 10)
	var wg sync.WaitGroup
	startWebhookSender(srv.URL, ch, &wg)

	a := Alert{
		Rule:     "sensitive-file-access",
		Severity: "critical",
		Message:  `"cat" accessed sensitive path "/etc/shadow"`,
		PID:      1234,
		Comm:     "cat",
		Filename: "/etc/shadow",
	}
	sendAlert(ch, a)

	select {
	case <-gotReq:
	case <-time.After(2 * time.Second):
		t.Fatal("webhook never reached the server within timeout")
	}

	mu.Lock()
	defer mu.Unlock()
	if received.Alert.Rule != "sensitive-file-access" {
		t.Errorf("expected rule sensitive-file-access, got %q", received.Alert.Rule)
	}
	if received.Text == "" {
		t.Errorf("expected a non-empty Slack-compatible text field, got empty")
	}
	if received.Alert.Filename != "/etc/shadow" {
		t.Errorf("expected filename /etc/shadow in nested alert, got %q", received.Alert.Filename)
	}
}

func TestSendAlert_NilChannel_NoPanic(t *testing.T) {
	// If no -webhook flag is set, main.go passes a nil channel. This must
	// be a safe no-op, not a panic.
	sendAlert(nil, Alert{Rule: "test"})
}

func TestSendAlert_FullChannel_DropsWithoutBlocking(t *testing.T) {
	ch := make(chan Alert, 1)
	ch <- Alert{Rule: "filler"} // fill the buffer

	done := make(chan struct{})
	go func() {
		sendAlert(ch, Alert{Rule: "should be dropped"})
		close(done)
	}()

	select {
	case <-done:
		// good: returned immediately instead of blocking
	case <-time.After(1 * time.Second):
		t.Fatal("sendAlert blocked on a full channel instead of dropping")
	}
}

func TestWebhookSender_ServerReturns500_LogsAndContinues(t *testing.T) {
	// The server fails every request. The sender must log the unexpected
	// status and keep draining — a second alert still has to reach the
	// server, proving the goroutine didn't die or block on the first 500.
	gotReq := make(chan struct{}, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		gotReq <- struct{}{}
	}))
	defer srv.Close()

	ch := make(chan Alert, 10)
	var wg sync.WaitGroup
	startWebhookSender(srv.URL, ch, &wg)

	sendAlert(ch, Alert{Rule: "first"})
	sendAlert(ch, Alert{Rule: "second"})

	for i := 0; i < 2; i++ {
		select {
		case <-gotReq:
		case <-time.After(2 * time.Second):
			t.Fatalf("expected request %d to reach the server despite repeated 500s", i+1)
		}
	}
}

func TestWebhookSender_UnreachableURL_LogsAndContinues(t *testing.T) {
	// Nothing listens on port 1, so every POST errors. The sender must log
	// the error and keep draining rather than block or die: both buffered
	// alerts should be consumed from the channel.
	ch := make(chan Alert, 10)
	var wg sync.WaitGroup
	startWebhookSender("http://127.0.0.1:1", ch, &wg)

	sendAlert(ch, Alert{Rule: "first"})
	sendAlert(ch, Alert{Rule: "second"})

	deadline := time.After(2 * time.Second)
	for len(ch) > 0 {
		select {
		case <-deadline:
			t.Fatalf("sender stopped draining on POST errors; %d alert(s) left in queue", len(ch))
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestWebhookSender_MarshalError(t *testing.T) {
	// Skipped deliberately: Alert (and thus webhookPayload) contains only
	// string/uint fields, which always marshal cleanly. There is no
	// non-contrived way to force a json.Marshal error through this path, so
	// rather than fake one we document that the branch is unreachable here.
	t.Skip("webhookPayload always marshals cleanly; no realistic way to trigger the marshal-error branch")
}
