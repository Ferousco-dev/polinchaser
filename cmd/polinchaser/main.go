// Command polinchaser is the web service: webhooks, health and (later) the dashboard API.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Ferousco-dev/polinchaser/internal/auth"
	"github.com/Ferousco-dev/polinchaser/internal/config"
	"github.com/Ferousco-dev/polinchaser/internal/dashboard"
	"github.com/Ferousco-dev/polinchaser/internal/db"
	"github.com/Ferousco-dev/polinchaser/internal/notify"
	"github.com/Ferousco-dev/polinchaser/internal/queue"
	"github.com/Ferousco-dev/polinchaser/internal/server"
	"github.com/Ferousco-dev/polinchaser/internal/store"
	"github.com/Ferousco-dev/polinchaser/internal/webhook"
	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		slog.Error("invalid configuration", "err", err)
		os.Exit(1)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "web")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("database", "err", err)
		os.Exit(1)
	}
	defer pool.Close()
	if applied, err := db.Migrate(ctx, pool); err != nil {
		log.Error("migrate", "err", err)
		os.Exit(1)
	} else if len(applied) > 0 {
		log.Info("migrations applied", "names", applied)
	}

	q := queue.New(pool)
	deps := server.Deps{DB: pool, Queue: q, Log: log}
	if cfg.GitHubEnabled() {
		deps.Webhook = &webhook.Handler{Secret: cfg.GitHubWebhookSecret, Store: &store.Store{Pool: pool}, Queue: q, Log: log}
	} else {
		log.Warn("GitHub App not configured: webhook endpoint disabled")
	}
	if cfg.ResendWebhookSecret != "" {
		key, err := notify.ParseWebhookSecret(cfg.ResendWebhookSecret)
		if err != nil {
			log.Error("resend webhook secret", "err", err)
			os.Exit(1)
		}
		deps.ResendWebhook = &notify.WebhookHandler{Key: key, Pool: pool, Log: log}
	}
	if cfg.BaseURL == "" {
		log.Warn("BASE_URL not set: dashboard and passkey sign-in disabled")
	} else {
		svc, err := auth.New(pool, cfg.BaseURL, cfg.AdminSetupToken)
		if err != nil {
			log.Error("auth", "err", err)
			os.Exit(1)
		}
		dash := &dashboard.Dashboard{Pool: pool, Info: dashboard.Info{
			Env: cfg.Env, GitHubConfigured: cfg.GitHubEnabled(), EmailConfigured: cfg.ResendAPIKey != "", Rules: scanner.BuiltinRules()}}
		dash.Auth = &auth.HTTP{Svc: svc, BaseURL: cfg.BaseURL, Log: log, Audit: dash.WriteAudit,
			Limiter: auth.NewLimiter(10, time.Minute), TrustedHop: cfg.TrustedProxyHops}
		deps.Mount = dash.Routes
		if cfg.AdminSetupToken == "" {
			log.Info("ADMIN_SETUP_TOKEN not set: first-time passkey setup is disabled")
		}
	}
	srv := &http.Server{
		Addr: cfg.ListenAddr, Handler: server.New(deps),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("listening", "config", cfg.String())
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server", "err", err)
		os.Exit(1)
	}
	log.Info("shutdown complete")
}
