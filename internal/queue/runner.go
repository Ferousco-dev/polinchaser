package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Handler processes a job. Return a PermanentError to dead-letter immediately.
type Handler func(ctx context.Context, j *Job) error

type permanent struct{ error }

func (p permanent) Unwrap() error { return p.error }

// Permanent marks err as non-retryable.
func Permanent(err error) error { return permanent{err} }

type Runner struct {
	Queue       *Queue
	Handlers    map[string]Handler
	Concurrency int
	Lease       time.Duration
	Poll        time.Duration
	Log         *slog.Logger
	WorkerID    string
}

// Run blocks until ctx is cancelled, then waits for in-flight jobs to finish
// (graceful shutdown). Jobs interrupted mid-run are recovered by lease expiry.
func (r *Runner) Run(ctx context.Context) {
	if r.Concurrency <= 0 {
		r.Concurrency = 1
	}
	if r.Poll == 0 {
		r.Poll = time.Second
	}
	if r.Lease == 0 {
		r.Lease = 5 * time.Minute
	}
	if r.Log == nil {
		r.Log = slog.Default()
	}
	if r.WorkerID == "" {
		h, _ := os.Hostname()
		r.WorkerID = fmt.Sprintf("%s-%d", h, os.Getpid())
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); r.recoverLoop(ctx) }()
	for i := 0; i < r.Concurrency; i++ {
		wg.Add(1)
		go func(n int) { defer wg.Done(); r.loop(ctx, fmt.Sprintf("%s/%d", r.WorkerID, n)) }(i)
	}
	wg.Wait()
}

func (r *Runner) recoverLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		if n, err := r.Queue.RecoverStale(ctx); err != nil && ctx.Err() == nil {
			r.Log.Error("recover stale jobs", "err", err)
		} else if n > 0 {
			r.Log.Warn("recovered stale jobs", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (r *Runner) loop(ctx context.Context, id string) {
	for ctx.Err() == nil {
		j, err := r.Queue.Claim(ctx, id, r.Lease)
		if err != nil {
			if ctx.Err() == nil {
				r.Log.Error("claim job", "err", err)
			}
			sleep(ctx, r.Poll)
			continue
		}
		if j == nil {
			sleep(ctx, r.Poll)
			continue
		}
		r.execute(ctx, id, j)
	}
}

func (r *Runner) execute(ctx context.Context, id string, j *Job) {
	log := r.Log.With("job_id", j.ID, "kind", j.Kind, "attempt", j.Attempts)
	h, ok := r.Handlers[j.Kind]
	var err error
	if !ok {
		err = Permanent(fmt.Errorf("no handler for kind %q", j.Kind))
	} else {
		jobCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		hb := make(chan struct{})
		go func() { // heartbeat keeps the lease alive for long scans
			defer close(hb)
			t := time.NewTicker(r.Lease / 3)
			defer t.Stop()
			for {
				select {
				case <-jobCtx.Done():
					return
				case <-t.C:
					if e := r.Queue.Extend(jobCtx, j.ID, id, r.Lease); errors.Is(e, ErrLostLease) {
						log.Error("lease lost; abandoning job")
						cancel()
						return
					}
				}
			}
		}()
		err = safeCall(jobCtx, h, j)
		cancel()
		<-hb
	}
	// Use a fresh context so completion is recorded even during shutdown.
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err == nil {
		if e := r.Queue.Complete(dbCtx, j.ID, id); e != nil {
			log.Error("complete job", "err", e)
		}
		return
	}
	var p permanent
	isPerm := errors.As(err, &p)
	log.Error("job failed", "err", err, "permanent", isPerm)
	if e := r.Queue.Fail(dbCtx, j, id, err, isPerm); e != nil {
		log.Error("record job failure", "err", e)
	}
}

func safeCall(ctx context.Context, h Handler, j *Job) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("handler panic: %v", rec)
		}
	}()
	return h(ctx, j)
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
