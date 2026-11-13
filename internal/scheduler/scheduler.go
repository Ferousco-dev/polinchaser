// Package scheduler queues periodic rescans so a repository is re-checked even
// when nobody pushes, and re-checked when the detection rules change.
//
// It only enqueues ordinary scan jobs; the worker does the scanning. It is safe
// to run in every worker: each job carries a dedupe key for (repository, rule
// version, interval bucket), so at most one scan is queued per bucket.
package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Ferousco-dev/polinchaser/internal/queue"
	"github.com/Ferousco-dev/polinchaser/internal/webhook"
)

const MinInterval = time.Hour

type Enqueuer interface {
	Enqueue(ctx context.Context, kind string, payload any, o queue.EnqueueOpts) (int64, bool, error)
}

type Scheduler struct {
	Pool        *pgxpool.Pool
	Queue       Enqueuer
	Interval    time.Duration                    // rescan a repository at least this often; 0 disables
	RuleVersion string                           // current detection rule version (used when VersionFn is nil)
	VersionFn   func(ctx context.Context) string // optional: rule version as of now (changes after a threat-intel refresh)
	Batch       int                              // max repositories queued per tick (default 50)
	Tick        time.Duration                    // how often to look (default 1m)
	Log         *slog.Logger
	Now         func() time.Time
}

// Run blocks until ctx is cancelled. With Interval 0 it returns immediately.
func (s *Scheduler) Run(ctx context.Context) {
	if s.Interval <= 0 {
		s.Log.Info("scheduled rescans disabled")
		return
	}
	tick := s.Tick
	if tick <= 0 {
		tick = time.Minute
	}
	s.Log.Info("scheduled rescans enabled", "interval", s.Interval.String(), "rules", s.RuleVersion)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		if n, err := s.RunOnce(ctx); err != nil {
			s.Log.Error("scheduler tick failed", "err", err)
		} else if n > 0 {
			s.Log.Info("scheduled scans queued", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunOnce queues scans for repositories that are due and returns how many jobs
// were newly created. Due means: active, not archived, installation live, and
// no completed scan within Interval using the current rule version. Failed and
// incomplete scans do not count as coverage, so those repositories are retried
// (at most once per interval bucket).
func (s *Scheduler) RunOnce(ctx context.Context) (int, error) {
	if s.Interval <= 0 {
		return 0, nil
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	batch := s.Batch
	if batch <= 0 {
		batch = 50
	}
	ruleVersion := s.RuleVersion
	if s.VersionFn != nil {
		ruleVersion = s.VersionFn(ctx)
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT r.id, r.installation_id
		FROM repositories r
		JOIN installations i ON i.id = r.installation_id
		WHERE r.active AND NOT r.archived AND i.removed_at IS NULL AND NOT i.suspended
		  AND NOT EXISTS (
		    SELECT 1 FROM scans s
		    WHERE s.repository_id = r.id
		      AND s.status IN ('clean','findings_detected')
		      AND s.rule_version = $2
		      AND s.created_at > now() - $1::interval)
		ORDER BY (SELECT max(s.created_at) FROM scans s WHERE s.repository_id = r.id) NULLS FIRST, r.id
		LIMIT $3`, s.Interval.String(), ruleVersion, batch)
	if err != nil {
		return 0, fmt.Errorf("find due repositories: %w", err)
	}
	type due struct{ repo, inst int64 }
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.repo, &d.inst); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	bucket := now().Unix() / int64(s.Interval.Seconds())
	created := 0
	for _, d := range list {
		key := fmt.Sprintf("sched:%d:%s:%d", d.repo, ruleVersion, bucket)
		_, ok, err := s.Queue.Enqueue(ctx, webhook.KindScan,
			webhook.ScanJob{InstallationID: d.inst, RepositoryID: d.repo, Trigger: "scheduled"},
			queue.EnqueueOpts{DedupeKey: key})
		if err != nil {
			return created, fmt.Errorf("enqueue repo %d: %w", d.repo, err)
		}
		if ok {
			created++
		}
	}
	return created, nil
}
