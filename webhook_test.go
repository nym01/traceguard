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
	startWebhookSender(srv.URL, ch)

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
