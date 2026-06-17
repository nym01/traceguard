package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
func startWebhookSender(url string, alerts <-chan Alert) {
	client := &http.Client{Timeout: 5 * time.Second}
	go func() {
		for a := range alerts {
			payload := webhookPayload{
				Text:  fmt.Sprintf("[%s] %s: %s", a.Severity, a.Rule, a.Message),
				Alert: a,
			}
			body, err := json.Marshal(payload)
			if err != nil {
				log.Printf("webhook: marshal error: %v", err)
				continue
			}
			resp, err := client.Post(url, "application/json", bytes.NewReader(body))
			if err != nil {
				log.Printf("webhook: post error: %v", err)
				continue
			}
			resp.Body.Close()
			if resp.StatusCode >= 300 {
				log.Printf("webhook: unexpected status %d", resp.StatusCode)
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
		log.Println("webhook: queue full, dropping alert")
	}
}
