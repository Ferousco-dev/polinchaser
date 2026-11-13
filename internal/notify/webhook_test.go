package notify_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Ferousco-dev/polinchaser/internal/notify"
	"github.com/Ferousco-dev/polinchaser/internal/testutil"
)

var whKey = []byte("0123456789abcdef0123456789abcdef")

type whEnv struct {
	t    *testing.T
	pool *pgxpool.Pool
	h    *notify.WebhookHandler
	now  time.Time
}

func newWH(t *testing.T) *whEnv {
	pool := testutil.Pool(t)
	ctx := context.Background()
	var inst, repo, scan, nid int64
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(pool.QueryRow(ctx, `INSERT INTO installations (github_installation_id, account_id, account_login, account_type) VALUES (1,1,'a','User') RETURNING id`).Scan(&inst))
	must(pool.QueryRow(ctx, `INSERT INTO repositories (installation_id, github_repo_id, full_name) VALUES ($1,1,'a/b') RETURNING id`, inst).Scan(&repo))
	must(pool.QueryRow(ctx, `INSERT INTO scans (installation_id, repository_id, trigger, commit_sha, status) VALUES ($1,$2,'push','a','findings_detected') RETURNING id`, inst, repo).Scan(&scan))
	must(pool.QueryRow(ctx, `INSERT INTO notifications (installation_id, scan_id, kind) VALUES ($1,$2,'alert') RETURNING id`, inst, scan).Scan(&nid))
	_, err := pool.Exec(ctx, `INSERT INTO notification_deliveries (notification_id, recipient, status, provider_id) VALUES ($1,'a@example.com','sent','em_123')`, nid)
	must(err)
	e := &whEnv{t: t, pool: pool, now: time.Now()}
	e.h = &notify.WebhookHandler{Key: whKey, Pool: pool, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return e.now }}
	return e
}

func sign(id string, ts time.Time, body string) (string, string) {
	t := strconv.FormatInt(ts.Unix(), 10)
	mac := hmac.New(sha256.New, whKey)
	mac.Write([]byte(id + "." + t + "." + body))
	return t, "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (e *whEnv) post(id string, ts time.Time, body, sigOverride string) int {
	t, sig := sign(id, ts, body)
	if sigOverride != "" {
		sig = sigOverride
	}
	r := httptest.NewRequest("POST", "/webhooks/resend", strings.NewReader(body))
	r.Header.Set("svix-id", id)
	r.Header.Set("svix-timestamp", t)
	r.Header.Set("svix-signature", sig)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w.Code
}

func (e *whEnv) feedback() (fb *string, lastErr *string) {
	_ = e.pool.QueryRow(context.Background(), `SELECT feedback, last_error FROM notification_deliveries WHERE provider_id='em_123'`).Scan(&fb, &lastErr)
	return
}

const bounce = `{"type":"email.bounced","data":{"email_id":"em_123"}}`

func TestBounceRecordedOnlyWithValidSignature(t *testing.T) {
	e := newWH(t)
	if c := e.post("msg_1", e.now, bounce, "v1,"+base64.StdEncoding.EncodeToString([]byte("forged"))); c != 401 {
		t.Errorf("forged signature: %d, want 401", c)
	}
	if fb, _ := e.feedback(); fb != nil {
		t.Fatal("forged webhook changed state")
	}
	if c := e.post("msg_1", e.now, bounce, ""); c != 204 {
		t.Fatalf("valid webhook: %d", c)
	}
	fb, le := e.feedback()
	if fb == nil || *fb != "bounced" || le == nil || *le != "bounced" {
		t.Errorf("feedback=%v last_error=%v", fb, le)
	}
}

func TestSignatureCoversTheBody(t *testing.T) {
	e := newWH(t)
	_, goodSig := sign("msg_1", e.now, bounce)
	tampered := strings.Replace(bounce, "em_123", "em_999", 1)
	if c := e.post("msg_1", e.now, tampered, goodSig); c != 401 {
		t.Errorf("tampered body accepted: %d", c)
	}
}

func TestStaleTimestampRejectedAndReplayIgnored(t *testing.T) {
	e := newWH(t)
	if c := e.post("msg_old", e.now.Add(-10*time.Minute), bounce, ""); c != 400 {
		t.Errorf("stale timestamp: %d, want 400", c)
	}
	if c := e.post("msg_2", e.now, `{"type":"email.delivered","data":{"email_id":"em_123"}}`, ""); c != 204 {
		t.Fatal("delivered rejected")
	}
	// Replaying the same event id is acknowledged but not reprocessed.
	if c := e.post("msg_2", e.now, bounce, ""); c == 401 {
		t.Fatal("unexpected 401")
	}
	var n int
	_ = e.pool.QueryRow(context.Background(), `SELECT count(*) FROM resend_events WHERE event_id='msg_2'`).Scan(&n)
	if n != 1 {
		t.Errorf("event recorded %d times", n)
	}
}

func TestLaterDeliveredDoesNotHideABounce(t *testing.T) {
	e := newWH(t)
	e.post("msg_a", e.now, bounce, "")
	e.post("msg_b", e.now, `{"type":"email.delivered","data":{"email_id":"em_123"}}`, "")
	if fb, _ := e.feedback(); fb == nil || *fb != "bounced" {
		t.Errorf("feedback = %v, want bounced", fb)
	}
}

func TestIrrelevantAndUnknownEventsAreAcknowledged(t *testing.T) {
	e := newWH(t)
	for i, body := range []string{`{"type":"email.opened","data":{"email_id":"em_123"}}`, `{"type":"email.bounced","data":{"email_id":"em_unknown"}}`} {
		if c := e.post("msg_x"+strconv.Itoa(i), e.now, body, ""); c != 204 {
			t.Errorf("event %d: %d, want 204", i, c)
		}
	}
	if fb, _ := e.feedback(); fb != nil {
		t.Error("unrelated event changed the delivery")
	}
}

func TestMissingHeadersAndOversizedBody(t *testing.T) {
	e := newWH(t)
	r := httptest.NewRequest("POST", "/webhooks/resend", strings.NewReader(bounce))
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Errorf("no headers: %d", w.Code)
	}
	r = httptest.NewRequest("POST", "/webhooks/resend", bytes.NewReader(bytes.Repeat([]byte("a"), 2<<20)))
	w = httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: %d", w.Code)
	}
}

func TestParseWebhookSecret(t *testing.T) {
	good := "whsec_" + base64.StdEncoding.EncodeToString(whKey)
	if k, err := notify.ParseWebhookSecret(good); err != nil || !bytes.Equal(k, whKey) {
		t.Errorf("good secret: %v", err)
	}
	for _, bad := range []string{"", "secret", "whsec_!!!notbase64", "whsec_" + base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := notify.ParseWebhookSecret(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
