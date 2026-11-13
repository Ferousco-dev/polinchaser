package retention_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Ferousco-dev/polinchaser/internal/retention"
	"github.com/Ferousco-dev/polinchaser/internal/testutil"
)

func exec(t *testing.T, p *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := p.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, p *pgxpool.Pool, sql string) (n int) {
	t.Helper()
	if err := p.QueryRow(context.Background(), sql).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return
}

func TestExpiredSuppressionsReopenAndAreAudited(t *testing.T) {
	p := testutil.Pool(t)
	var inst, repo int64
	_ = p.QueryRow(context.Background(), `INSERT INTO installations (github_installation_id, account_id, account_login, account_type) VALUES (1,1,'a','User') RETURNING id`).Scan(&inst)
	_ = p.QueryRow(context.Background(), `INSERT INTO repositories (installation_id, github_repo_id, full_name) VALUES ($1,1,'a/b') RETURNING id`, inst).Scan(&repo)
	ins := `INSERT INTO findings (installation_id, repository_id, fingerprint, rule_id, rule_version, category, severity, confidence, path, title, explanation, remediation, status, suppressed_until, suppression_reason, notified_at)
		VALUES ($1,$2,$3,'R','1','c','high','low','p','t','e','r',$4,$5::timestamptz,'because',now())`
	exec(t, p, ins, inst, repo, "expired", "accepted_risk", "2000-01-01")
	exec(t, p, ins, inst, repo, "future", "accepted_risk", "2999-01-01")
	exec(t, p, ins, inst, repo, "forever", "false_positive", nil)

	r := &retention.Retention{Pool: p, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	st, err := r.RunOnce(context.Background())
	if err != nil || st.SuppressionsExpired != 1 {
		t.Fatalf("expired=%d err=%v, want 1", st.SuppressionsExpired, err)
	}
	if n := count(t, p, `SELECT count(*) FROM findings WHERE fingerprint='expired' AND status='open' AND suppressed_until IS NULL AND notified_at IS NULL`); n != 1 {
		t.Error("expired suppression was not reopened and re-armed for alerting")
	}
	if n := count(t, p, `SELECT count(*) FROM findings WHERE status IN ('accepted_risk','false_positive')`); n != 2 {
		t.Errorf("unexpired suppressions touched: %d remain, want 2", n)
	}
	if n := count(t, p, `SELECT count(*) FROM audit_logs WHERE action='finding.suppression_expired' AND actor='system'`); n != 1 {
		t.Error("expiry not audited")
	}
	if st, _ := r.RunOnce(context.Background()); st.SuppressionsExpired != 0 {
		t.Error("second run expired more rows")
	}
}

func TestPurgeKeepsRecentAndRemovesOld(t *testing.T) {
	p := testutil.Pool(t)
	exec(t, p, `INSERT INTO webhook_deliveries (delivery_id, event, received_at) VALUES ('old','push', now() - interval '31 days'), ('new','push', now())`)
	exec(t, p, `INSERT INTO jobs (kind, state, finished_at) VALUES ('scan','succeeded', now() - interval '15 days'), ('scan','succeeded', now()), ('scan','queued', NULL), ('scan','dead', now() - interval '20 days')`)
	exec(t, p, `INSERT INTO audit_logs (actor, action, created_at) VALUES ('x','old', now() - interval '400 days'), ('x','new', now())`)
	var inst, repo int64
	_ = p.QueryRow(context.Background(), `INSERT INTO installations (github_installation_id, account_id, account_login, account_type) VALUES (1,1,'a','User') RETURNING id`).Scan(&inst)
	_ = p.QueryRow(context.Background(), `INSERT INTO repositories (installation_id, github_repo_id, full_name) VALUES ($1,1,'a/b') RETURNING id`, inst).Scan(&repo)
	exec(t, p, `INSERT INTO scans (installation_id, repository_id, trigger, commit_sha, status, created_at) VALUES ($1,$2,'push','a','clean', now() - interval '200 days'), ($1,$2,'push','b','clean', now())`, inst, repo)

	r := &retention.Retention{Pool: p, ScanDays: 180, AuditDays: 365, Batch: 1, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := count(t, p, `SELECT count(*) FROM webhook_deliveries`); n != 1 {
		t.Errorf("webhook_deliveries = %d, want 1", n)
	}
	if n := count(t, p, `SELECT count(*) FROM jobs`); n != 3 { // old succeeded gone; queued, fresh succeeded and recent dead stay
		t.Errorf("jobs = %d, want 3", n)
	}
	if n := count(t, p, `SELECT count(*) FROM audit_logs WHERE action='old'`); n != 0 {
		t.Error("old audit row kept")
	}
	if n := count(t, p, `SELECT count(*) FROM audit_logs WHERE action='new'`); n != 1 {
		t.Error("recent audit row deleted")
	}
	if n := count(t, p, `SELECT count(*) FROM scans`); n != 1 {
		t.Errorf("scans = %d, want 1", n)
	}

	// With retention off, nothing old is removed.
	exec(t, p, `INSERT INTO scans (installation_id, repository_id, trigger, commit_sha, status, created_at) VALUES ($1,$2,'push','c','clean', now() - interval '900 days')`, inst, repo)
	r.ScanDays, r.AuditDays = 0, 0
	if _, err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := count(t, p, `SELECT count(*) FROM scans`); n != 2 {
		t.Errorf("scans = %d with retention off, want 2", n)
	}
}
