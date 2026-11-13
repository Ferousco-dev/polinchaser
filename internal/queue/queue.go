// Package queue is a durable PostgreSQL job queue: SKIP LOCKED claiming,
// leases, exponential backoff, dead-lettering and stale-lease recovery.
package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Job struct {
	ID          int64
	Kind        string
	Payload     json.RawMessage
	Attempts    int
	MaxAttempts int
}

type EnqueueOpts struct {
	DedupeKey   string    // identical keys enqueue at most once, ever
	RunAt       time.Time // zero = now
	MaxAttempts int       // zero = 5
}

type Queue struct {
	pool        *pgxpool.Pool
	BackoffBase time.Duration
	BackoffMax  time.Duration
}

func New(pool *pgxpool.Pool) *Queue {
	return &Queue{pool: pool, BackoffBase: 10 * time.Second, BackoffMax: time.Hour}
}

// Enqueue returns created=false when DedupeKey already exists.
func (q *Queue) Enqueue(ctx context.Context, kind string, payload any, o EnqueueOpts) (id int64, created bool, err error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, false, err
	}
	if o.MaxAttempts == 0 {
		o.MaxAttempts = 5
	}
	if o.RunAt.IsZero() {
		o.RunAt = time.Now()
	}
	var key *string
	if o.DedupeKey != "" {
		key = &o.DedupeKey
	}
	err = q.pool.QueryRow(ctx, `
		INSERT INTO jobs (kind, payload, dedupe_key, max_attempts, run_at)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (dedupe_key) DO NOTHING
		RETURNING id`, kind, b, key, o.MaxAttempts, o.RunAt).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	return id, err == nil, err
}

// Claim leases the next runnable job, or returns (nil, nil) when none is due.
func (q *Queue) Claim(ctx context.Context, worker string, lease time.Duration) (*Job, error) {
	var j Job
	err := q.pool.QueryRow(ctx, `
		UPDATE jobs SET state='running', locked_by=$1, attempts=attempts+1,
		       lease_expires_at = now() + $2::interval, updated_at=now()
		WHERE id = (SELECT id FROM jobs WHERE state='queued' AND run_at <= now()
		            ORDER BY run_at, id FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING id, kind, payload, attempts, max_attempts`,
		worker, fmt.Sprintf("%d milliseconds", lease.Milliseconds())).
		Scan(&j.ID, &j.Kind, &j.Payload, &j.Attempts, &j.MaxAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &j, nil
}

// ErrLostLease means another worker took over; the caller must abandon the job.
var ErrLostLease = errors.New("queue: lease lost")

func (q *Queue) Extend(ctx context.Context, id int64, worker string, lease time.Duration) error {
	return q.owned(ctx, `UPDATE jobs SET lease_expires_at = now() + $3::interval, updated_at=now()
		WHERE id=$1 AND locked_by=$2 AND state='running'`, id, worker, fmt.Sprintf("%d milliseconds", lease.Milliseconds()))
}

func (q *Queue) Complete(ctx context.Context, id int64, worker string) error {
	return q.owned(ctx, `UPDATE jobs SET state='succeeded', finished_at=now(), updated_at=now(), locked_by=NULL, lease_expires_at=NULL
		WHERE id=$1 AND locked_by=$2 AND state='running'`, id, worker)
}

// Fail reschedules with exponential backoff, or dead-letters when attempts
// are exhausted or the error is permanent.
func (q *Queue) Fail(ctx context.Context, j *Job, worker string, cause error, permanent bool) error {
	msg := truncate(cause.Error(), 2000)
	if permanent || j.Attempts >= j.MaxAttempts {
		return q.owned(ctx, `UPDATE jobs SET state='dead', last_error=$3, finished_at=now(), updated_at=now(), locked_by=NULL, lease_expires_at=NULL
			WHERE id=$1 AND locked_by=$2 AND state='running'`, j.ID, worker, msg)
	}
	return q.owned(ctx, `UPDATE jobs SET state='queued', last_error=$3, run_at=now()+$4::interval, updated_at=now(), locked_by=NULL, lease_expires_at=NULL
		WHERE id=$1 AND locked_by=$2 AND state='running'`, j.ID, worker, msg,
		fmt.Sprintf("%d milliseconds", q.backoff(j.Attempts).Milliseconds()))
}

func (q *Queue) backoff(attempt int) time.Duration {
	d := q.BackoffBase
	for i := 1; i < attempt && d < q.BackoffMax; i++ {
		d *= 2
	}
	return min(d, q.BackoffMax)
}

// RecoverStale returns jobs whose worker vanished (expired lease) to the
// queue, or dead-letters them when out of attempts.
func (q *Queue) RecoverStale(ctx context.Context) (int64, error) {
	tag, err := q.pool.Exec(ctx, `
		UPDATE jobs SET
		  state = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'queued' END,
		  last_error = 'lease expired (worker lost)',
		  finished_at = CASE WHEN attempts >= max_attempts THEN now() END,
		  locked_by=NULL, lease_expires_at=NULL, updated_at=now()
		WHERE state='running' AND lease_expires_at < now()`)
	return tag.RowsAffected(), err
}

// Depth returns queued job count (for metrics and health).
func (q *Queue) Depth(ctx context.Context) (n int64, err error) {
	err = q.pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE state='queued'`).Scan(&n)
	return
}

func (q *Queue) owned(ctx context.Context, sql string, args ...any) error {
	tag, err := q.pool.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLostLease
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
