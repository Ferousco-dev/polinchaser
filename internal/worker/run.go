package worker

import (
	"context"
	"errors"
	"log/slog"

	"github.com/Ferousco-dev/polinchaser/internal/config"
	"github.com/Ferousco-dev/polinchaser/internal/github"
	"github.com/Ferousco-dev/polinchaser/internal/intel"
	"github.com/Ferousco-dev/polinchaser/internal/notify"
	"github.com/Ferousco-dev/polinchaser/internal/osv"
	"github.com/Ferousco-dev/polinchaser/internal/policy"
	"github.com/Ferousco-dev/polinchaser/internal/queue"
	"github.com/Ferousco-dev/polinchaser/internal/retention"
	"github.com/Ferousco-dev/polinchaser/internal/scheduler"
	"github.com/Ferousco-dev/polinchaser/internal/store"
	"github.com/Ferousco-dev/polinchaser/internal/webhook"
	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Run starts the job runner plus the scheduler, intel refresher and retention loops.
// It blocks until ctx is cancelled. Used by polinchaser-worker and by the web
// binary when RUN_WORKER=true (single-service deployments).
func Run(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, log *slog.Logger) error {
	if !cfg.GitHubEnabled() {
		return errors.New("GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY and GITHUB_WEBHOOK_SECRET are required for the worker")
	}
	key, err := github.ParsePrivateKey(cfg.GitHubPrivateKeyPEM)
	if err != nil {
		return err
	}
	rules := scanner.BuiltinRules()
	intelMgr := &intel.Manager{Pool: pool, Builtin: rules, Log: log}
	sc := &Scanner{Rules: intelMgr,
		Store: &store.Store{Pool: pool}, Forge: github.NewClient(cfg.GitHubAppID, key, cfg.GitHubAPIBase),
		Engine: scanner.New(rules), RuleVersion: rules.Version, Policy: policy.Default(),
		Timeout: cfg.ScanTimeout, Archive: github.DefaultArchiveLimits, Log: log,
	}
	q := queue.New(pool)
	if cfg.OSVEnabled {
		sc.Deps = osv.New(cfg.OSVAPIBase)
		log.Info("dependency advisory lookups enabled: package names and versions are sent to OSV")
	}
	handlers := map[string]queue.Handler{webhook.KindScan: sc.Handle}
	if cfg.EmailEnabled() {
		sc.Notify = q
		handlers[notify.KindNotify] = (&notify.Service{Store: sc.Store, Sender: notify.NewResend(cfg.ResendAPIKey, cfg.ResendAPIBase), From: cfg.EmailFrom,
			BaseURL: cfg.BaseURL, DefaultRecipients: cfg.NotifyRecipients, DefaultMin: scanner.Severity(cfg.NotifyMinSeverity), Log: log}).Handle
	} else {
		log.Warn("Resend not configured: alert emails disabled")
	}
	sched := &scheduler.Scheduler{Pool: pool, Queue: q, Interval: cfg.ScheduleInterval, RuleVersion: rules.Version, VersionFn: intelMgr.Version, Log: log}
	ref := &intel.Refresher{Pool: pool, URLs: cfg.IntelFeedURLs, Client: intel.NewHTTPClient(cfg.Env == "development"), Interval: cfg.IntelRefreshInterval, Log: log}
	go ref.Run(ctx)
	ret := &retention.Retention{Pool: pool, ScanDays: cfg.RetentionScanDays, AuditDays: cfg.RetentionAuditDays, Log: log}
	go ret.Run(ctx)
	go sched.Run(ctx)
	r := &queue.Runner{Queue: q, Concurrency: cfg.WorkerConcurrency, Lease: cfg.JobLease, Log: log, Handlers: handlers}
	log.Info("worker started", "config", cfg.String(), "rules", rules.Version)
	r.Run(ctx)
	log.Info("worker stopped")
	return nil
}
