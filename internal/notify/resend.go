// Package notify builds and delivers security alert emails through Resend.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Email struct {
	From    string
	To      []string
	Subject string
	HTML    string
	Text    string
}

// Sender is the delivery boundary (faked in tests).
type Sender interface {
	// Send delivers the email. idempotencyKey makes retries safe.
	Send(ctx context.Context, e Email, idempotencyKey string) (providerID string, err error)
}

// SendError says whether retrying can help.
type SendError struct {
	Status    int
	Retryable bool
	Message   string
}

func (e *SendError) Error() string { return fmt.Sprintf("resend: status %d: %s", e.Status, e.Message) }

type Resend struct {
	apiKey string
	base   string
	http   *http.Client
}

func NewResend(apiKey, base string) *Resend {
	if base == "" {
		base = "https://api.resend.com"
	}
	return &Resend{apiKey: apiKey, base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 20 * time.Second}}
}

func (r *Resend) Send(ctx context.Context, e Email, idempotencyKey string) (string, error) {
	b, err := json.Marshal(map[string]any{"from": e.From, "to": e.To, "subject": e.Subject, "html": e.HTML, "text": e.Text})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.base+"/emails", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+r.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "polinchaser")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		// Network errors never echo the request (and so never the key).
		return "", &SendError{Retryable: true, Message: "network error contacting Resend"}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		msg := "request rejected"
		var e struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &e) == nil && e.Message != "" {
			msg = e.Message
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return "", &SendError{Status: resp.StatusCode, Retryable: resp.StatusCode == 429 || resp.StatusCode >= 500, Message: msg}
	}
	var out struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(data, &out)
	return out.ID, nil
}
