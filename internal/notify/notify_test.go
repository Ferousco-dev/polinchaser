package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ferousco-dev/polinchaser/internal/notify"
	"github.com/Ferousco-dev/polinchaser/internal/queue"
	"github.com/Ferousco-dev/polinchaser/internal/store"
	"github.com/Ferousco-dev/polinchaser/internal/testutil"
	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

func TestResendClientRequestAndErrors(t *testing.T) {
	var gotAuth, gotKey string
	var body map[string]any
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotKey = r.Header.Get("Authorization"), r.Header.Get("Idempotency-Key")
		json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(status)
		if status == 200 {
			w.Write([]byte(`{"id":"em_123"}`))
		} else {
			w.Write([]byte(`{"message":"invalid from address"}`))
		}
	}))
	defer srv.Close()
	c := notify.NewResend("re_secretkey", srv.URL)
	id, err := c.Send(t.Context(), notify.Email{From: "a@x.dev", To: []string{"b@y.dev"}, Subject: "s", HTML: "<p>h</p>", Text: "t"}, "key-1")
	if err != nil || id != "em_123" || gotAuth != "Bearer re_secretkey" || gotKey != "key-1" || body["subject"] != "s" {
		t.Fatalf("%v %q %q %q %v", err, id, gotAuth, gotKey, body)
	}
	for code, retry := range map[int]bool{429: true, 500: true, 503: true, 422: false, 401: false, 403: false} {
		status = code
		_, err := c.Send(t.Context(), notify.Email{}, "")
		var se *notify.SendError
		if !errors.As(err, &se) || se.Retryable != retry {
			t.Errorf("status %d: %v", code, err)
		}
		if err != nil && strings.Contains(err.Error(), "re_secretkey") {
			t.Fatal("API key leaked in error")
		}
	}
	srv.Close()
	_, err = c.Send(t.Context(), notify.Email{}, "")
	var se *notify.SendError
	if !errors.As(err, &se) || !se.Retryable || strings.Contains(err.Error(), "re_secretkey") {
		t.Fatalf("network error: %v", err)
	}
}

func alert(fs ...notify.AlertFinding) notify.Alert {
	return notify.Alert{Repo: "acme/app", Branch: "main", Commit: "a1b2c3d4e5f6", Author: "Dev", Time: time.Date(2026, 11, 13, 14, 32, 0, 0, time.UTC),
		Findings: fs, ReportURL: "https://pc.example.com/scans/9"}
}

func TestRenderEscapesAttackerControlledFields(t *testing.T) {
	evil := `<script>alert(1)</script>`
	a := alert(notify.AlertFinding{Path: evil + ".js", Line: 3, Title: `"><img src=x onerror=alert(1)>`, Severity: "high", Confidence: "high"})
	a.Branch, a.Author, a.Repo = evil, evil, "acme/app\r\nBcc: x@evil.dev"
	subj, html, text, err := notify.Render(a)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "<script>") || strings.Contains(html, "<img src=x") {
		t.Fatal("unescaped HTML in email")
	}
	if strings.ContainsAny(subj, "\r\n") {
		t.Fatalf("header injection in subject: %q", subj)
	}
	if !strings.Contains(text, "acme/app") {
		t.Fatal("text part missing")
	}
}

func TestRenderHonestyAndContent(t *testing.T) {
	heur := alert(notify.AlertFinding{Path: "a.js", Line: 7, Title: "Obfuscation", Severity: "critical", Confidence: "medium"})
	subj, html, text, _ := notify.Render(heur)
	if strings.Contains(subj, "Known malware") || strings.Contains(html, "exact known-malware") {
		t.Fatal("heuristic presented as confirmed")
	}
	for _, want := range []string{"View Security Report", "https://pc.example.com/scans/9", "a1b2c3d", "13 November 2026, 14:32 UTC", "a.js:7", "heuristic"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
	if strings.Contains(html+text, "blocked by security policy") || strings.Contains(html, "Deployment blocked") {
		t.Fatal("must not claim deployment is blocked")
	}
	if !strings.Contains(text, "only blocked if required status checks") {
		t.Fatal("deployment caveat missing")
	}
	conf := alert(notify.AlertFinding{Path: "a.js", Title: "Known PolinRider indicator matched", Severity: "critical", Confidence: "confirmed_signature"})
	if s, _, _, _ := notify.Render(conf); !strings.Contains(s, "Known malware indicator") {
		t.Fatal(s)
	}
	cred := alert(notify.AlertFinding{Path: ".env", Title: "t", Severity: "high", Confidence: "high", Category: "credential_exposure"})
	if _, _, tx, _ := notify.Render(cred); !strings.Contains(tx, "does not invalidate it") {
		t.Fatal("credential advice missing")
	}
}

func TestRenderGroupsManyFindingsIntoOneEmail(t *testing.T) {
	var fs []notify.AlertFinding
	for i := 0; i < 300; i++ {
		fs = append(fs, notify.AlertFinding{Path: fmt.Sprintf("f%d.js", i), Title: "t", Severity: "high", Confidence: "high"})
	}
	_, html, _, _ := notify.Render(alert(fs...))
	if strings.Count(html, "border-left:3px") != 25 || !strings.Contains(html, "275 more") || !strings.Contains(html, "Findings (300)") {
		t.Fatal("findings not capped/summarised")
	}
}

type fakeSender struct {
	mu    sync.Mutex
	sent  []notify.Email
	keys  []string
	fail  map[string]error
	calls map[string]int
}

func (f *fakeSender) Send(_ context.Context, e notify.Email, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[e.To[0]]++
	if err := f.fail[e.To[0]]; err != nil {
		return "", err
	}
	f.sent = append(f.sent, e)
	f.keys = append(f.keys, key)
	return "em_" + e.To[0], nil
}

type env struct {
	t      *testing.T
	st     *store.Store
	svc    *notify.Service
	sender *fakeSender
	inst   int64
	repo   int64
}

func newEnv(t *testing.T, recipients ...string) *env {
	pool := testutil.Pool(t)
	st := &store.Store{Pool: pool}
	ctx := context.Background()
	inst, _ := st.UpsertInstallation(ctx, store.Installation{GitHubID: 1, AccountID: 1, Login: "acme", Type: "User", Selection: "all"})
	repo, _ := st.UpsertRepo(ctx, inst, store.RepoInput{GitHubID: 2, FullName: "acme/app"})
	sender := &fakeSender{fail: map[string]error{}}
	return &env{t: t, st: st, sender: sender, inst: inst, repo: repo.ID, svc: &notify.Service{
		Store: st, Sender: sender, From: "alerts@x.dev", BaseURL: "https://pc.example.com", DefaultRecipients: recipients,
		DefaultMin: scanner.SeverityHigh, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}
}

func (e *env) scan(commit string, fs ...scanner.Finding) int64 {
	ctx := context.Background()
	id, err := e.st.CreateScan(ctx, store.ScanInput{InstallationID: e.inst, RepositoryID: e.repo, Trigger: "push", CommitSHA: commit, Branch: "main", RuleVersion: "t"})
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.st.SaveFindings(ctx, id, e.inst, e.repo, commit, fs); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) run(scanID int64) error {
	b, _ := json.Marshal(notify.Payload{ScanID: scanID})
	return e.svc.Handle(context.Background(), &queue.Job{Payload: b})
}

func finding(path string, sev scanner.Severity) scanner.Finding {
	return scanner.Finding{RuleID: "R", RuleVersion: "1", Category: scanner.CatSuspiciousCode, Severity: sev, Confidence: scanner.ConfidenceHigh,
		Path: path, LineStart: 4, Title: "T " + path, Explanation: "e", Remediation: "r", Evidence: "SECRET-EVIDENCE-PAYLOAD", Fingerprint: "fp-" + path}
}

func TestOneGroupedEmailPerRecipientAndNoEvidence(t *testing.T) {
	e := newEnv(t, "a@x.dev", "b@x.dev")
	var fs []scanner.Finding
	for i := 0; i < 40; i++ {
		fs = append(fs, finding(fmt.Sprintf("f%d.js", i), scanner.SeverityHigh))
	}
	if err := e.run(e.scan("c1", fs...)); err != nil {
		t.Fatal(err)
	}
	if len(e.sender.sent) != 2 {
		t.Fatalf("want 2 emails (one per recipient), got %d", len(e.sender.sent))
	}
	for _, m := range e.sender.sent {
		if strings.Contains(m.HTML+m.Text, "SECRET-EVIDENCE-PAYLOAD") {
			t.Fatal("evidence leaked into email")
		}
	}
}

func TestBelowThresholdAndNoRecipientsSendNothing(t *testing.T) {
	e := newEnv(t, "a@x.dev")
	if err := e.run(e.scan("c1", finding("a.js", scanner.SeverityMedium))); err != nil || len(e.sender.sent) != 0 {
		t.Fatalf("%v %d", err, len(e.sender.sent))
	}
	e2 := newEnv(t)
	if err := e2.run(e2.scan("c1", finding("a.js", scanner.SeverityCritical))); err != nil || len(e2.sender.sent) != 0 {
		t.Fatal("sent with no recipients")
	}
}

func TestAlreadyAlertedFindingsAreNotResent(t *testing.T) {
	e := newEnv(t, "a@x.dev")
	f := finding("a.js", scanner.SeverityHigh)
	e.run(e.scan("c1", f))
	e.run(e.scan("c2", f)) // same finding reappears in the next commit/PR sync
	if len(e.sender.sent) != 1 {
		t.Fatalf("duplicate alert for same finding: %d", len(e.sender.sent))
	}
	e.run(e.scan("c3", f, finding("new.js", scanner.SeverityHigh)))
	if len(e.sender.sent) != 2 || strings.Contains(e.sender.sent[1].HTML, "a.js") && !strings.Contains(e.sender.sent[1].HTML, "new.js") {
		t.Fatal("new finding not alerted")
	}
}

func TestRerunOfSameJobIsIdempotent(t *testing.T) {
	e := newEnv(t, "a@x.dev")
	id := e.scan("c1", finding("a.js", scanner.SeverityHigh))
	e.run(id)
	e.run(id)
	if len(e.sender.sent) != 1 {
		t.Fatal("job re-run sent twice")
	}
}

func TestPartialFailureRetriesOnlyFailedRecipient(t *testing.T) {
	e := newEnv(t, "ok@x.dev", "flaky@x.dev")
	e.sender.fail["flaky@x.dev"] = &notify.SendError{Status: 503, Retryable: true}
	id := e.scan("c1", finding("a.js", scanner.SeverityHigh))
	if err := e.run(id); err == nil {
		t.Fatal("retryable failure must surface for queue retry")
	}
	delete(e.sender.fail, "flaky@x.dev")
	if err := e.run(id); err != nil {
		t.Fatal(err)
	}
	if e.sender.calls["ok@x.dev"] != 1 || e.sender.calls["flaky@x.dev"] != 2 {
		t.Fatalf("calls %v", e.sender.calls)
	}
	var sent int
	e.st.Pool.QueryRow(context.Background(), `SELECT count(*) FROM notification_deliveries WHERE status='sent'`).Scan(&sent)
	if sent != 2 {
		t.Fatal("delivery tracking wrong")
	}
}

func TestPermanentRejectionIsRecordedNotRetried(t *testing.T) {
	e := newEnv(t, "bad@x.dev")
	e.sender.fail["bad@x.dev"] = &notify.SendError{Status: 422, Message: "invalid"}
	if err := e.run(e.scan("c1", finding("a.js", scanner.SeverityHigh))); err != nil {
		t.Fatalf("permanent rejection must not retry: %v", err)
	}
	var st string
	e.st.Pool.QueryRow(context.Background(), `SELECT status FROM notification_deliveries`).Scan(&st)
	if st != "failed" {
		t.Fatal(st)
	}
}

func TestPerInstallationSettingsOverrideDefaults(t *testing.T) {
	e := newEnv(t, "default@x.dev")
	e.st.Pool.Exec(context.Background(), `INSERT INTO notification_settings(installation_id, recipients, min_severity) VALUES ($1,'{team@x.dev}','critical')`, e.inst)
	e.run(e.scan("c1", finding("a.js", scanner.SeverityHigh)))
	if len(e.sender.sent) != 0 {
		t.Fatal("below per-installation threshold was sent")
	}
	e.run(e.scan("c2", finding("b.js", scanner.SeverityCritical)))
	if len(e.sender.sent) != 1 || e.sender.sent[0].To[0] != "team@x.dev" {
		t.Fatalf("%+v", e.sender.sent)
	}
	e.st.Pool.Exec(context.Background(), `UPDATE notification_settings SET enabled=false`)
	e.run(e.scan("c3", finding("c.js", scanner.SeverityCritical)))
	if len(e.sender.sent) != 1 {
		t.Fatal("disabled installation still emailed")
	}
}

func TestSuppressedFindingsAreNotAlerted(t *testing.T) {
	e := newEnv(t, "a@x.dev")
	id := e.scan("c1", finding("a.js", scanner.SeverityHigh))
	e.st.Pool.Exec(context.Background(), `UPDATE findings SET status='false_positive'`)
	e.run(id)
	if len(e.sender.sent) != 0 {
		t.Fatal("false positive alerted")
	}
}
