package queue_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ferousco-dev/polinchaser/internal/queue"
	"github.com/Ferousco-dev/polinchaser/internal/testutil"
)

func newQ(t *testing.T) *queue.Queue {
	q := queue.New(testutil.Pool(t))
	q.BackoffBase = 50 * time.Millisecond
	return q
}

func TestEnqueueDedupe(t *testing.T) {
	q, ctx := newQ(t), context.Background()
	_, c1, err := q.Enqueue(ctx, "scan", map[string]int{"a": 1}, queue.EnqueueOpts{DedupeKey: "delivery-1"})
	_, c2, err2 := q.Enqueue(ctx, "scan", map[string]int{"a": 1}, queue.EnqueueOpts{DedupeKey: "delivery-1"})
	if err != nil || err2 != nil || !c1 || c2 {
		t.Fatalf("dedupe failed: %v %v %v %v", c1, c2, err, err2)
	}
	n, _ := q.Depth(ctx)
	if n != 1 {
		t.Fatalf("depth %d", n)
	}
}

func TestClaimIsExclusiveUnderConcurrency(t *testing.T) {
	q, ctx := newQ(t), context.Background()
	const jobs = 20
	for i := 0; i < jobs; i++ {
		if _, _, err := q.Enqueue(ctx, "k", i, queue.EnqueueOpts{}); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	seen := map[int64]int{}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				j, err := q.Claim(ctx, "w", time.Minute)
				if err != nil {
					t.Error(err)
					return
				}
				if j == nil {
					return
				}
				mu.Lock()
				seen[j.ID]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != jobs {
		t.Fatalf("claimed %d of %d", len(seen), jobs)
	}
	for id, c := range seen {
		if c != 1 {
			t.Fatalf("job %d claimed %d times", id, c)
		}
	}
}

func TestRetryBackoffThenDead(t *testing.T) {
	q, ctx := newQ(t), context.Background()
	q.Enqueue(ctx, "k", nil, queue.EnqueueOpts{MaxAttempts: 2})
	j, _ := q.Claim(ctx, "w", time.Minute)
	if err := q.Fail(ctx, j, "w", errors.New("boom"), false); err != nil {
		t.Fatal(err)
	}
	if j2, _ := q.Claim(ctx, "w", time.Minute); j2 != nil {
		t.Fatal("job must wait for backoff")
	}
	time.Sleep(120 * time.Millisecond)
	j, _ = q.Claim(ctx, "w", time.Minute)
	if j == nil || j.Attempts != 2 {
		t.Fatalf("expected attempt 2: %+v", j)
	}
	q.Fail(ctx, j, "w", errors.New("boom"), false)
	time.Sleep(120 * time.Millisecond)
	if j3, _ := q.Claim(ctx, "w", time.Minute); j3 != nil {
		t.Fatal("exhausted job must be dead, not retried")
	}
}

func TestStaleLeaseRecovery(t *testing.T) {
	q, ctx := newQ(t), context.Background()
	q.Enqueue(ctx, "k", nil, queue.EnqueueOpts{})
	j, _ := q.Claim(ctx, "crashed-worker", 20*time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	if n, err := q.RecoverStale(ctx); err != nil || n != 1 {
		t.Fatalf("recover: %d %v", n, err)
	}
	if err := q.Complete(ctx, j.ID, "crashed-worker"); !errors.Is(err, queue.ErrLostLease) {
		t.Fatalf("old worker must lose lease, got %v", err)
	}
	if j2, _ := q.Claim(ctx, "w2", time.Minute); j2 == nil || j2.ID != j.ID {
		t.Fatal("recovered job not reclaimable")
	}
}

func TestRunnerHandlesSuccessPanicAndPermanent(t *testing.T) {
	q, ctx := newQ(t), context.Background()
	q.Enqueue(ctx, "ok", nil, queue.EnqueueOpts{})
	q.Enqueue(ctx, "panic", nil, queue.EnqueueOpts{MaxAttempts: 1})
	q.Enqueue(ctx, "perm", nil, queue.EnqueueOpts{})
	q.Enqueue(ctx, "unknown", nil, queue.EnqueueOpts{})
	var ok, perm atomic.Int32
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	r := &queue.Runner{Queue: q, Concurrency: 2, Poll: 10 * time.Millisecond, Handlers: map[string]queue.Handler{
		"ok":    func(context.Context, *queue.Job) error { ok.Add(1); return nil },
		"panic": func(context.Context, *queue.Job) error { panic("kaboom") },
		"perm":  func(context.Context, *queue.Job) error { perm.Add(1); return queue.Permanent(errors.New("bad input")) },
	}}
	go func() { r.Run(rctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var open int
		_ = testPoolCount(q, ctx, &open)
		if open == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not shut down")
	}
	if ok.Load() != 1 || perm.Load() != 1 {
		t.Fatalf("ok=%d perm=%d (permanent errors must not retry)", ok.Load(), perm.Load())
	}
}

func testPoolCount(q *queue.Queue, ctx context.Context, out *int) error {
	n, err := q.Depth(ctx)
	*out = int(n)
	return err
}
