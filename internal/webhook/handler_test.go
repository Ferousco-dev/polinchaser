package webhook_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Ferousco-dev/polinchaser/internal/queue"
	"github.com/Ferousco-dev/polinchaser/internal/store"
	"github.com/Ferousco-dev/polinchaser/internal/testutil"
	"github.com/Ferousco-dev/polinchaser/internal/webhook"
)

const secret = "whsec-test"

type env struct {
	t    *testing.T
	pool *pgxpool.Pool
	st   *store.Store
	h    *webhook.Handler
	n    int
}

func newEnv(t *testing.T) *env {
	pool := testutil.Pool(t)
	st := &store.Store{Pool: pool}
	return &env{t: t, pool: pool, st: st, h: &webhook.Handler{
		Secret: secret, Store: st, Queue: queue.New(pool), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}
}

func sig(body string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func (e *env) send(event, delivery, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(body))
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-GitHub-Delivery", delivery)
	req.Header.Set("X-Hub-Signature-256", sig(body))
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *env) count(sql string, args ...any) int {
	var n int
	if err := e.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) install(ghInstall int64, repoID int64) {
	e.t.Helper()
	e.n++
	body := fmt.Sprintf(`{"action":"created","installation":{"id":%d,"account":{"id":5,"login":"acme","type":"Organization"},"repository_selection":"selected"},
		"repositories":[{"id":%d,"full_name":"acme/app","default_branch":"main"}]}`, ghInstall, repoID)
	if rec := e.send("installation", fmt.Sprintf("inst-%d-%d", ghInstall, e.n), body); rec.Code != 202 {
		e.t.Fatalf("install: %d %s", rec.Code, rec.Body)
	}
}

func pushBody(inst, repo int64, ref, after string, deleted bool) string {
	return fmt.Sprintf(`{"ref":%q,"before":"1111111111111111111111111111111111111111","after":%q,"deleted":%t,
		"repository":{"id":%d,"full_name":"acme/app"},"installation":{"id":%d}}`, ref, after, deleted, repo, inst)
}

const sha1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestForgedSignatureRejectedWithNoSideEffects(t *testing.T) {
	e := newEnv(t)
	body := pushBody(1, 1, "refs/heads/main", sha1, false)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-GitHub-Delivery", "d1")
	req.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64))
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("got %d", rec.Code)
	}
	if e.count(`SELECT count(*) FROM webhook_deliveries`) != 0 || e.count(`SELECT count(*) FROM jobs`) != 0 {
		t.Fatal("forged request had side effects")
	}
	req.Header.Del("X-Hub-Signature-256")
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatal("missing signature must be 401")
	}
}

func TestMethodAndHeaderValidation(t *testing.T) {
	e := newEnv(t)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 405 {
		t.Fatal(rec.Code)
	}
	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig(body))
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("missing headers: %d", rec.Code)
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	e := newEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/", io.LimitReader(zeros{}, 26<<20))
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 413 {
		t.Fatalf("got %d", rec.Code)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { return len(p), nil }

func TestInstallationRegistersReposAndQueuesInitialScan(t *testing.T) {
	e := newEnv(t)
	e.install(100, 900)
	if e.count(`SELECT count(*) FROM repositories WHERE active`) != 1 || e.count(`SELECT count(*) FROM jobs WHERE kind='scan'`) != 1 {
		t.Fatal("install did not register repo and scan")
	}
	var trig string
	_ = e.pool.QueryRow(context.Background(), `SELECT payload->>'trigger' FROM jobs`).Scan(&trig)
	if trig != "install" {
		t.Fatal(trig)
	}
}

func TestPushQueuesScanAndDuplicateDeliveryIsIdempotent(t *testing.T) {
	e := newEnv(t)
	e.install(100, 900)
	body := pushBody(100, 900, "refs/heads/feature/x", sha1, false)
	if rec := e.send("push", "dup-1", body); rec.Code != 202 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec := e.send("push", "dup-1", body) // replay
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "duplicate") {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body)
	}
	// Same commit re-delivered under a NEW delivery id must still not double-scan.
	e.send("push", "dup-2", body)
	if n := e.count(`SELECT count(*) FROM jobs WHERE payload->>'trigger'='push'`); n != 1 {
		t.Fatalf("want 1 push job, got %d", n)
	}
}

func TestPushIgnoredCases(t *testing.T) {
	e := newEnv(t)
	e.install(100, 900)
	for name, body := range map[string]string{
		"tag":             pushBody(100, 900, "refs/tags/v1", sha1, false),
		"deleted flag":    pushBody(100, 900, "refs/heads/x", sha1, true),
		"zero sha":        pushBody(100, 900, "refs/heads/x", strings.Repeat("0", 40), false),
		"unknown repo":    pushBody(100, 12345, "refs/heads/x", sha1, false),
		"unknown install": pushBody(777, 900, "refs/heads/x", sha1, false),
	} {
		if rec := e.send("push", "ign-"+name, body); rec.Code != 202 {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	if n := e.count(`SELECT count(*) FROM jobs WHERE payload->>'trigger'='push'`); n != 0 {
		t.Fatalf("ignored events queued %d jobs", n)
	}
}

func TestCrossInstallationIsolation(t *testing.T) {
	e := newEnv(t)
	e.install(100, 900) // installation A owns repo 900
	e.install(200, 901) // installation B owns repo 901
	// Installation B's event claims repo 900, which only A owns.
	e.send("push", "x1", pushBody(200, 900, "refs/heads/main", sha1, false))
	if n := e.count(`SELECT count(*) FROM jobs WHERE payload->>'trigger'='push'`); n != 0 {
		t.Fatal("event for another installation's repository queued a scan")
	}
	e.send("push", "x2", pushBody(100, 900, "refs/heads/main", sha1, false))
	if n := e.count(`SELECT count(*) FROM jobs WHERE payload->>'trigger'='push'`); n != 1 {
		t.Fatal("legitimate event not queued")
	}
	// The queued job must point at installation A's internal ids.
	if e.count(`SELECT count(*) FROM jobs j JOIN repositories r ON r.id=(j.payload->>'repository_id')::bigint
		WHERE j.payload->>'trigger'='push' AND r.installation_id=(j.payload->>'installation_id')::bigint`) != 1 {
		t.Fatal("job installation/repository mismatch")
	}
}

func TestPullRequestLifecycle(t *testing.T) {
	e := newEnv(t)
	e.install(100, 900)
	pr := func(action, head string) string {
		return fmt.Sprintf(`{"action":%q,"number":7,"pull_request":{"head":{"sha":%q,"ref":"fix"},"base":{"sha":"bbbb","ref":"main"}},
			"repository":{"id":900,"full_name":"acme/app"},"installation":{"id":100}}`, action, head)
	}
	e.send("pull_request", "p1", pr("opened", sha1))
	e.send("pull_request", "p2", pr("synchronize", strings.Repeat("c", 40))) // new commit => rescan
	e.send("pull_request", "p3", pr("reopened", strings.Repeat("c", 40)))    // same head => deduped
	e.send("pull_request", "p4", pr("closed", strings.Repeat("d", 40)))      // ignored
	e.send("pull_request", "p5", pr("labeled", strings.Repeat("e", 40)))     // ignored
	if n := e.count(`SELECT count(*) FROM jobs WHERE payload->>'trigger'='pull_request'`); n != 2 {
		t.Fatalf("want 2 PR scans, got %d", n)
	}
	var base string
	_ = e.pool.QueryRow(context.Background(), `SELECT payload->>'base_sha' FROM jobs WHERE payload->>'trigger'='pull_request' LIMIT 1`).Scan(&base)
	if base != "bbbb" {
		t.Fatalf("base sha not captured: %q", base)
	}
}

func TestInstallationDeletedDeactivates(t *testing.T) {
	e := newEnv(t)
	e.install(100, 900)
	e.send("installation", "del", `{"action":"deleted","installation":{"id":100}}`)
	if e.count(`SELECT count(*) FROM repositories WHERE active`) != 0 || e.count(`SELECT count(*) FROM installations WHERE removed_at IS NOT NULL`) != 1 {
		t.Fatal("not deactivated")
	}
	e.send("push", "after-del", pushBody(100, 900, "refs/heads/main", sha1, false))
	if e.count(`SELECT count(*) FROM jobs WHERE payload->>'trigger'='push'`) != 0 {
		t.Fatal("removed installation still scanned")
	}
}

func TestReposAddedAndRemoved(t *testing.T) {
	e := newEnv(t)
	e.install(100, 900)
	e.send("installation_repositories", "r1", `{"action":"added","installation":{"id":100},"repository_selection":"selected",
		"repositories_added":[{"id":901,"full_name":"acme/two"}],"repositories_removed":[]}`)
	e.send("installation_repositories", "r2", `{"action":"removed","installation":{"id":100},
		"repositories_added":[],"repositories_removed":[{"id":900,"full_name":"acme/app"}]}`)
	if e.count(`SELECT count(*) FROM repositories WHERE active AND github_repo_id=901`) != 1 || e.count(`SELECT count(*) FROM repositories WHERE active AND github_repo_id=900`) != 0 {
		t.Fatal("repo set wrong")
	}
}

func TestTransientFailureReleasesDeliveryForRedelivery(t *testing.T) {
	e := newEnv(t)
	e.install(100, 900)
	dead, err := pgxpool.New(context.Background(), os.Getenv("PC_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	dead.Close() // every enqueue will fail
	good := e.h.Queue
	e.h.Queue = queue.New(dead)
	body := pushBody(100, 900, "refs/heads/main", sha1, false)
	if rec := e.send("push", "flaky", body); rec.Code != 500 {
		t.Fatalf("want 500, got %d", rec.Code)
	}
	if e.count(`SELECT count(*) FROM webhook_deliveries WHERE delivery_id='flaky'`) != 0 {
		t.Fatal("failed delivery must be released")
	}
	e.h.Queue = good
	if rec := e.send("push", "flaky", body); rec.Code != 202 {
		t.Fatalf("redelivery: %d", rec.Code)
	}
	if e.count(`SELECT count(*) FROM jobs WHERE payload->>'trigger'='push'`) != 1 {
		t.Fatal("redelivery did not queue scan")
	}
}
