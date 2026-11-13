package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

type pinger struct{ err error }

func (p pinger) Ping(context.Context) error { return p.err }

type depth struct{}

func (depth) Depth(context.Context) (int64, error) { return 3, nil }

func do(h http.Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestHealthAndReadiness(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	up := New(Deps{DB: pinger{}, Queue: depth{}, Log: log})
	if rec := do(up, "GET", "/healthz"); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	rec := do(up, "GET", "/readyz")
	if rec.Code != 200 || rec.Header().Get("X-Request-ID") == "" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	down := New(Deps{DB: pinger{errors.New("conn refused to postgres://u:secret@h")}, Queue: depth{}, Log: log})
	rec = do(down, "GET", "/readyz")
	if rec.Code != 503 || contains(rec.Body.String(), "secret") {
		t.Fatalf("unready must be 503 without leaking details: %d %s", rec.Code, rec.Body)
	}
}

func TestWebhookRouteWhenUnconfigured(t *testing.T) {
	h := New(Deps{DB: pinger{}, Queue: depth{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if rec := do(h, "POST", "/webhooks/github"); rec.Code != 503 {
		t.Fatal(rec.Code)
	}
	if rec := do(h, "GET", "/webhooks/github"); rec.Code != 405 {
		t.Fatal(rec.Code)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
