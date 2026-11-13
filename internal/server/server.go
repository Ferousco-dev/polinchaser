// Package server builds the HTTP handler for the web service.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

type Pinger interface {
	Ping(ctx context.Context) error
}
type Depther interface {
	Depth(ctx context.Context) (int64, error)
}

type Deps struct {
	DB      Pinger
	Queue   Depther
	Webhook http.Handler // nil when the GitHub App is not configured
	// ResendWebhook receives email delivery events; nil when no signing secret is configured.
	ResendWebhook http.Handler
	Log           *slog.Logger
	// Mount registers extra routes (the dashboard and its API). Optional.
	Mount func(*http.ServeMux)
}

func New(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := d.DB.Ping(ctx); err != nil {
			d.Log.Error("readiness: database unavailable", "err", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "database": "down"})
			return
		}
		depth, _ := d.Queue.Depth(ctx)
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "database": "up", "queue_depth": depth, "github_app_configured": d.Webhook != nil})
	})
	if d.Webhook != nil {
		mux.Handle("POST /webhooks/github", d.Webhook)
	} else {
		mux.HandleFunc("POST /webhooks/github", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "GitHub App is not configured on this server", http.StatusServiceUnavailable)
		})
	}
	if d.ResendWebhook != nil {
		mux.Handle("POST /webhooks/resend", d.ResendWebhook)
	} else {
		mux.HandleFunc("POST /webhooks/resend", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Resend webhooks are not configured on this server", http.StatusServiceUnavailable)
		})
	}
	if d.Mount != nil {
		d.Mount(mux)
	}
	return requestID(securityHeaders(mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// The dashboard is an operator console on its own subdomain: never index it.
		h.Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet, noimageindex")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b [8]byte
		_, _ = rand.Read(b[:])
		w.Header().Set("X-Request-ID", hex.EncodeToString(b[:]))
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
