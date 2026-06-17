package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// webhookPayload wraps the alert in a shape that's both Slack-compatible
// (Slack incoming webhooks only look at "text") and useful for generic
// JSON webhook receivers that want the structured fields too.
type webhookPayload struct {
	Text  string `json:"text"`
	Alert Alert  `json:"alert"`
}

// startWebhookSender launches one dedicated goroutine that drains the
// alerts channel and POSTs each one to url. Using a single goroutine
// (rather than one per alert) keeps this simple and avoids a goroutine
// explosion under a burst of alerts; the channel buffer absorbs short
// bursts, and if it's ever full we drop and log rather than blocking the
// detection pipeline on network I/O.
//
// wg lets the caller wait for a clean drain on shutdown: the goroutine
// signals wg.Done when its range loop exits, which happens once the alerts
// channel is closed and fully drained. So closing the channel at shutdown
// and waiting on wg flushes any still-queued alerts before exit rather than
// dropping them.
func startWebhookSender(url string, alerts <-chan Alert, wg *sync.WaitGroup) {
	client := &http.Client{Timeout: 5 * time.Second}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for a := range alerts {
			payload := webhookPayload{
				Text:  fmt.Sprintf("[%s] %s: %s", a.Severity, a.Rule, a.Message),
				Alert: a,
			}
			body, err := json.Marshal(payload)
			if err != nil {
				fmt.Fprintf(os.Stderr, "traceguard: webhook: marshal error: %v\n", err)
				continue
			}
			resp, err := client.Post(url, "application/json", bytes.NewReader(body))
			if err != nil {
				fmt.Fprintf(os.Stderr, "traceguard: webhook: post error: %v\n", err)
				continue
			}
			resp.Body.Close()
			if resp.StatusCode >= 300 {
				fmt.Fprintf(os.Stderr, "traceguard: webhook: unexpected status %d\n", resp.StatusCode)
			}
		}
	}()
}

// sendAlert is the non-blocking enqueue helper main.go's consumer will
// call after printing each alert. ch may be nil if no webhook is
// configured, in which case this is a no-op.
func sendAlert(ch chan Alert, a Alert) {
	if ch == nil {
		return
	}
	select {
	case ch <- a:
	default:
		fmt.Fprintln(os.Stderr, "traceguard: webhook: queue full, dropping alert")
	}
}
