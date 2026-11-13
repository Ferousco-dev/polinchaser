package scheduler_test

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Ferousco-dev/polinchaser/internal/queue"
	"github.com/Ferousco-dev/polinchaser/internal/scheduler"
	"github.com/Ferousco-dev/polinchaser/internal/testutil"
)

type fixture struct {
	pool *pgxpool.Pool
	q    *queue.Queue
	s    *scheduler.Scheduler
	inst int64
}

func newFixture(t *testing.T) *fixture {
	pool := testutil.Pool(t)
	f := &fixture{pool: pool, q: queue.New(pool)}
	f.s = &scheduler.Scheduler{Pool: pool, Queue: f.q, Interval: 24 * time.Hour, RuleVersion: "v2", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	must(t, pool.QueryRow(context.Background(), `INSERT INTO installations (github_installation_id, account_id, account_login, account_type) VALUES (1,1,'acme','Organization') RETURNING id`).Scan(&f.inst))
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) repo(t *testing.T, ghID int, extra string) int64 {
	var id int64
	must(t, f.pool.QueryRow(context.Background(), `INSERT INTO repositories (installation_id, github_repo_id, full_name`+extra+`) VALUES ($1,$2::bigint,'acme/r'||$2::bigint::text`+valuesFor(extra)+`) RETURNING id`, f.inst, ghID).Scan(&id))
	return id
}

func valuesFor(extra string) string {
	switch extra {
	case ", archived":
		return ", TRUE"
	case ", active":
		return ", FALSE"
	}
	return ""
}

func (f *fixture) scan(t *testing.T, repo int64, status, rules, age string) {
	_, err := f.pool.Exec(context.Background(), `INSERT INTO scans (installation_id, repository_id, trigger, commit_sha, status, rule_version, created_at)
		VALUES ($1,$2,'push','abc',$3,$4, now() - $5::interval)`, f.inst, repo, status, rules, age)
	must(t, err)
}

func (f *fixture) jobs(t *testing.T) int {
	var n int
	must(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM jobs WHERE kind='scan'`).Scan(&n))
	return n
}

func TestQueuesOnlyDueRepositories(t *testing.T) {
	f := newFixture(t)
	f.repo(t, 1, "") // never scanned
	stale := f.repo(t, 2, "")
	fresh := f.repo(t, 3, "")
	oldRules := f.repo(t, 4, "")
	failedOnly := f.repo(t, 5, "")
	f.scan(t, stale, "clean", "v2", "30 hours")
	f.scan(t, fresh, "clean", "v2", "2 hours")
	f.scan(t, oldRules, "clean", "v1", "2 hours")
	f.scan(t, failedOnly, "failed", "v2", "1 hour")

	n, err := f.s.RunOnce(context.Background())
	must(t, err)
	// never, stale, oldRules and failedOnly are due; fresh is not.
	if n != 4 || f.jobs(t) != 4 {
		t.Fatalf("queued %d (jobs %d), want 4", n, f.jobs(t))
	}
	var freshJobs int
	must(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM jobs WHERE payload->>'repository_id'=$1`, itoa(fresh)).Scan(&freshJobs))
	if freshJobs != 0 {
		t.Error("fresh repository was queued")
	}
}

func TestSecondTickAndSecondWorkerDoNotDuplicate(t *testing.T) {
	f := newFixture(t)
	f.repo(t, 1, "")
	if n, _ := f.s.RunOnce(context.Background()); n != 1 {
		t.Fatalf("first tick queued %d", n)
	}
	other := *f.s // a second worker running the same scheduler
	for i, s := range []*scheduler.Scheduler{f.s, &other} {
		if n, err := s.RunOnce(context.Background()); err != nil || n != 0 {
			t.Fatalf("repeat %d queued %d err %v", i, n, err)
		}
	}
	if f.jobs(t) != 1 {
		t.Fatalf("jobs = %d, want 1", f.jobs(t))
	}
}

func TestRuleChangeTriggersNewScanInSameInterval(t *testing.T) {
	f := newFixture(t)
	r := f.repo(t, 1, "")
	f.scan(t, r, "clean", "v2", "1 hour")
	if n, _ := f.s.RunOnce(context.Background()); n != 0 {
		t.Fatalf("up-to-date repo queued %d", n)
	}
	f.s.RuleVersion = "v3"
	if n, _ := f.s.RunOnce(context.Background()); n != 1 {
		t.Fatalf("rule change queued %d, want 1", n)
	}
}

func TestSkipsArchivedInactiveRemovedAndSuspended(t *testing.T) {
	f := newFixture(t)
	f.repo(t, 1, ", archived")
	f.repo(t, 2, ", active")
	var inst2 int64
	must(t, f.pool.QueryRow(context.Background(), `INSERT INTO installations (github_installation_id, account_id, account_login, account_type, removed_at) VALUES (2,2,'gone','User', now()) RETURNING id`).Scan(&inst2))
	_, err := f.pool.Exec(context.Background(), `INSERT INTO repositories (installation_id, github_repo_id, full_name) VALUES ($1,10,'gone/r')`, inst2)
	must(t, err)
	var inst3 int64
	must(t, f.pool.QueryRow(context.Background(), `INSERT INTO installations (github_installation_id, account_id, account_login, account_type, suspended) VALUES (3,3,'sus','User', TRUE) RETURNING id`).Scan(&inst3))
	_, err = f.pool.Exec(context.Background(), `INSERT INTO repositories (installation_id, github_repo_id, full_name) VALUES ($1,11,'sus/r')`, inst3)
	must(t, err)
	if n, err := f.s.RunOnce(context.Background()); err != nil || n != 0 {
		t.Fatalf("queued %d err %v, want 0", n, err)
	}
}

func TestBatchLimitAndDisabled(t *testing.T) {
	f := newFixture(t)
	for i := 1; i <= 5; i++ {
		f.repo(t, i, "")
	}
	f.s.Batch = 2
	if n, _ := f.s.RunOnce(context.Background()); n != 2 {
		t.Fatalf("batch queued %d, want 2", n)
	}
	f.s.Interval = 0
	if n, err := f.s.RunOnce(context.Background()); n != 0 || err != nil {
		t.Fatalf("disabled queued %d err %v", n, err)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestIntelRefreshVersionChangeTriggersRescan(t *testing.T) {
	f := newFixture(t)
	r := f.repo(t, 1, "")
	f.scan(t, r, "clean", "v2", "1 hour")
	cur := "v2"
	f.s.VersionFn = func(context.Context) string { return cur }
	if n, _ := f.s.RunOnce(context.Background()); n != 0 {
		t.Fatalf("queued %d before refresh", n)
	}
	cur = "v2+intel.abcd1234" // a feed refresh changed the active signatures
	if n, _ := f.s.RunOnce(context.Background()); n != 1 {
		t.Fatalf("queued %d after refresh, want 1", n)
	}
}
