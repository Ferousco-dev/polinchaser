// Package retention expires suppressions and purges old rows so the database
// (Neon's storage is limited) does not grow without bound. It is idempotent and
// safe to run in several workers at once: every statement is a bounded delete.
package retention

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const MinDays = 30

type Retention struct {
	Pool      *pgxpool.Pool
	ScanDays  int // delete scans (and their occurrences and notifications) older than this; 0 keeps forever
	AuditDays int // delete audit log rows older than this; 0 keeps forever
	Batch     int // rows per delete statement (default 5000)
	Every     time.Duration
	Log       *slog.Logger
}

type Stats struct {
	SuppressionsExpired int64
	Deleted             map[string]int64
}

func (r *Retention) Run(ctx context.Context) {
	every := r.Every
	if every <= 0 {
		every = time.Hour
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		st, err := r.RunOnce(ctx)
		switch {
		case err != nil:
			r.Log.Error("retention run failed", "err", err)
		case st.SuppressionsExpired > 0 || total(st.Deleted) > 0:
			r.Log.Info("retention run", "suppressions_expired", st.SuppressionsExpired, "deleted", st.Deleted)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func total(m map[string]int64) (n int64) {
	for _, v := range m {
		n += v
	}
	return
}

// RunOnce reopens findings whose suppression expired, then purges old rows.
func (r *Retention) RunOnce(ctx context.Context) (Stats, error) {
	st := Stats{Deleted: map[string]int64{}}
	// Expired suppressions reopen the finding and clear its alert marker, so the next
	// scan that still sees it alerts again. Each reopening is audited.
	tag, err := r.Pool.Exec(ctx, `
		WITH x AS (
		  UPDATE findings SET status='open', suppressed_until=NULL, suppression_reason=NULL, notified_at=NULL
		  WHERE status IN ('false_positive','accepted_risk') AND suppressed_until IS NOT NULL AND suppressed_until <= now()
		  RETURNING id, installation_id)
		INSERT INTO audit_logs (installation_id, actor, action, target)
		SELECT installation_id, 'system', 'finding.suppression_expired', 'finding:' || id FROM x`)
	if err != nil {
		return st, fmt.Errorf("expire suppressions: %w", err)
	}
	st.SuppressionsExpired = tag.RowsAffected()

	batch := r.Batch
	if batch <= 0 {
		batch = 5000
	}
	steps := []struct{ name, table, where string }{
		{"webhook_deliveries", "webhook_deliveries", `received_at < now() - interval '30 days'`},
		{"jobs_succeeded", "jobs", `state='succeeded' AND COALESCE(finished_at, updated_at) < now() - interval '14 days'`},
		{"jobs_dead", "jobs", `state='dead' AND COALESCE(finished_at, updated_at) < now() - interval '90 days'`},
		{"resend_events", "resend_events", `received_at < now() - interval '30 days'`},
		{"sessions", "sessions", `expires_at < now()`},
		{"auth_challenges", "auth_challenges", `expires_at < now()`},
		{"enrollment_tokens", "enrollment_tokens", `expires_at < now() - interval '1 day'`},
		{"resolved_findings", "findings", `status='resolved' AND last_detected_at < now() - interval '365 days'`},
	}
	if r.AuditDays > 0 {
		steps = append(steps, struct{ name, table, where string }{"audit_logs", "audit_logs", fmt.Sprintf(`created_at < now() - interval '%d days'`, r.AuditDays)})
	}
	if r.ScanDays > 0 {
		steps = append(steps, struct{ name, table, where string }{"scans", "scans", fmt.Sprintf(`created_at < now() - interval '%d days'`, r.ScanDays)})
	}
	for _, s := range steps {
		n, err := r.purge(ctx, s.table, s.where, batch)
		st.Deleted[s.name] = n
		if err != nil {
			return st, fmt.Errorf("purge %s: %w", s.name, err)
		}
	}
	return st, nil
}

// purge deletes matching rows in bounded batches (so no long locks) and returns the count.
// table and where are program constants or integers formatted above, never user input.
func (r *Retention) purge(ctx context.Context, table, where string, batch int) (int64, error) {
	q := fmt.Sprintf(`DELETE FROM %[1]s WHERE ctid IN (SELECT ctid FROM %[1]s WHERE %[2]s LIMIT %[3]d)`, table, where, batch)
	var total int64
	for i := 0; i < 200; i++ {
		tag, err := r.Pool.Exec(ctx, q)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < int64(batch) {
			break
		}
	}
	return total, nil
}
