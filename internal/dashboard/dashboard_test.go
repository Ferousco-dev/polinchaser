package dashboard_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Ferousco-dev/polinchaser/internal/auth"
	"github.com/Ferousco-dev/polinchaser/internal/dashboard"
	"github.com/Ferousco-dev/polinchaser/internal/server"
	"github.com/Ferousco-dev/polinchaser/internal/testutil"
	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

const base = "https://pc.example.com"

type env struct {
	t      *testing.T
	pool   *pgxpool.Pool
	h      http.Handler
	cookie *http.Cookie
	findID int64
	instID int64
}

type pinger struct{}

func (pinger) Ping(context.Context) error           { return nil }
func (pinger) Depth(context.Context) (int64, error) { return 0, nil }

func newEnv(t *testing.T) *env {
	pool := testutil.Pool(t)
	ctx := context.Background()
	svc, err := auth.New(pool, base, "")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := &dashboard.Dashboard{Pool: pool, Info: dashboard.Info{Env: "test", Rules: scanner.BuiltinRules()}}
	d.Auth = &auth.HTTP{Svc: svc, BaseURL: base, Log: log, Audit: d.WriteAudit, Limiter: auth.NewLimiter(1000, time.Minute)}

	// A valid session without a passkey ceremony: the table stores only a hash.
	var pid, inst, repo, scan int64
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(pool.QueryRow(ctx, `INSERT INTO passkeys (credential_id, credential, name) VALUES ('\x01','{}','test') RETURNING id`).Scan(&pid))
	tok := "test-session-token"
	sum := sha256.Sum256([]byte(tok))
	_, err = pool.Exec(ctx, `INSERT INTO sessions (token_hash, passkey_id, expires_at) VALUES ($1,$2, now() + interval '1 hour')`, sum[:], pid)
	must(err)
	must(pool.QueryRow(ctx, `INSERT INTO installations (github_installation_id, account_id, account_login, account_type) VALUES (1,1,'acme','Organization') RETURNING id`).Scan(&inst))
	must(pool.QueryRow(ctx, `INSERT INTO repositories (installation_id, github_repo_id, full_name) VALUES ($1,1,'acme/app') RETURNING id`, inst).Scan(&repo))
	must(pool.QueryRow(ctx, `INSERT INTO scans (installation_id, repository_id, trigger, commit_sha, status) VALUES ($1,$2,'push','abc123','findings_detected') RETURNING id`, inst, repo).Scan(&scan))
	e := &env{t: t, pool: pool, instID: inst}
	must(pool.QueryRow(ctx, `INSERT INTO findings (installation_id, repository_id, fingerprint, rule_id, rule_version, category, severity, confidence, path, title, explanation, remediation)
		VALUES ($1,$2,'fp1','PC-TEST','1','malware','high','low','a.js','Suspicious','why','fix') RETURNING id`, inst, repo).Scan(&e.findID))
	e.h = server.New(server.Deps{DB: pinger{}, Queue: pinger{}, Log: log, Mount: d.Routes})
	e.cookie = &http.Cookie{Name: d.Auth.CookieName(), Value: tok}
	return e
}

func (e *env) do(method, path, body string, authed bool, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, base+path, strings.NewReader(body))
	if authed {
		r.AddCookie(e.cookie)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func TestAPIRequiresSession(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/api/overview", "/api/repositories", "/api/scans", "/api/scans/1", "/api/findings", "/api/findings/1", "/api/system", "/api/intel", "/api/observability", "/api/audit", "/api/installations"} {
		if w := e.do("GET", p, "", false, ""); w.Code != 401 {
			t.Errorf("%s without session: %d, want 401", p, w.Code)
		}
	}
	if w := e.do("GET", "/api/overview", "", true, ""); w.Code != 200 {
		t.Fatalf("authed overview: %d %s", w.Code, w.Body)
	}
}

func TestEveryResponseIsNoindexWithStrictCSP(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/", "/findings/1", "/enroll", "/robots.txt", "/assets/app.js", "/api/overview", "/api/nope", "/healthz", "/favicon.svg"} {
		w := e.do("GET", p, "", false, "")
		if got := w.Header().Get("X-Robots-Tag"); !strings.Contains(got, "noindex") || !strings.Contains(got, "nofollow") {
			t.Errorf("%s: X-Robots-Tag=%q", p, got)
		}
		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: weak CSP %q", p, csp)
		}
	}
	if b := e.do("GET", "/robots.txt", "", false, "").Body.String(); !strings.Contains(b, "Disallow: /") {
		t.Errorf("robots.txt: %q", b)
	}
}

func TestIndexHasNoindexMetaAndNoInlineScript(t *testing.T) {
	w := newEnv(t).do("GET", "/", "", false, "")
	b := w.Body.String()
	if !strings.Contains(b, `name="robots"`) || !strings.Contains(b, "noindex") {
		t.Error("index.html lacks robots noindex meta")
	}
	for _, bad := range []string{"<script>", "onclick=", "style=\""} {
		if strings.Contains(b, bad) {
			t.Errorf("index.html contains inline %q", bad)
		}
	}
}

func TestSPAFallbackDoesNotSwallowAPI(t *testing.T) {
	e := newEnv(t)
	if w := e.do("GET", "/api/does-not-exist", "", false, ""); w.Code != 404 || strings.Contains(w.Body.String(), "<html") {
		t.Errorf("unknown api path: %d", w.Code)
	}
	if w := e.do("GET", "/scans/12", "", false, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "<html") {
		t.Errorf("deep link should serve the app shell: %d", w.Code)
	}
}

func TestFindingStatusRequiresReasonAndIsAudited(t *testing.T) {
	e := newEnv(t)
	path := "/api/findings/" + itoa(e.findID)
	if w := e.do("PATCH", path, `{"status":"false_positive"}`, true, base); w.Code != 400 {
		t.Errorf("suppress without reason: %d", w.Code)
	}
	if w := e.do("PATCH", path, `{"status":"false_positive","reason":"short"}`, true, base); w.Code != 400 {
		t.Errorf("short reason: %d", w.Code)
	}
	if w := e.do("PATCH", path, `{"status":"bogus","reason":"a long enough reason"}`, true, base); w.Code != 400 {
		t.Errorf("bad status: %d", w.Code)
	}
	if w := e.do("PATCH", path, `{"status":"false_positive","reason":"vendored minified bundle"}`, false, base); w.Code != 401 {
		t.Errorf("unauthenticated patch: %d", w.Code)
	}
	if w := e.do("PATCH", path, `{"status":"false_positive","reason":"vendored minified bundle"}`, true, "https://evil.example"); w.Code == 200 {
		t.Error("cross-origin patch accepted")
	}
	if w := e.do("PATCH", path, `{"status":"false_positive","reason":"vendored minified bundle"}`, true, base); w.Code != 200 {
		t.Fatalf("valid patch: %d %s", w.Code, w.Body)
	}
	var st string
	_ = e.pool.QueryRow(context.Background(), `SELECT status FROM findings WHERE id=$1`, e.findID).Scan(&st)
	if st != "false_positive" {
		t.Errorf("status = %s", st)
	}
	var n int
	_ = e.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE action LIKE '%finding%'`).Scan(&n)
	if n == 0 {
		t.Error("finding change was not audited")
	}
}

func TestFilterValidationAndInjectionSafety(t *testing.T) {
	e := newEnv(t)
	for _, q := range []string{"severity=bogus", "status=x'%3Bdrop%20table%20findings--", "confidence=zzz", "limit=-1&offset=-5"} {
		w := e.do("GET", "/api/findings?"+q, "", true, "")
		if w.Code == 200 && strings.Contains(q, "bogus") {
			t.Errorf("%s accepted", q)
		}
		if w.Code >= 500 {
			t.Errorf("%s -> %d", q, w.Code)
		}
	}
	var n int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM findings`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("findings table damaged: %v %d", err, n)
	}
	if w := e.do("GET", "/api/findings?q=%25%27%22", "", true, ""); w.Code != 200 {
		t.Errorf("search with special chars: %d", w.Code)
	}
}

func TestObservabilityIsZeroFilledAndBounded(t *testing.T) {
	e := newEnv(t)
	for days, want := range map[string]int{"": 14, "7": 7, "30": 30, "90": 90, "9999": 14, "abc": 14} {
		w := e.do("GET", "/api/observability?days="+days, "", true, "")
		if w.Code != 200 {
			t.Fatalf("days=%s: %d %s", days, w.Code, w.Body)
		}
		var out struct {
			Scans []map[string]any `json:"scans"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if len(out.Scans) != want {
			t.Errorf("days=%q: %d points, want %d", days, len(out.Scans), want)
		}
	}
}

func TestNotificationSettingsValidation(t *testing.T) {
	e := newEnv(t)
	path := "/api/installations/" + itoa(e.instID) + "/notifications"
	for name, body := range map[string]string{
		"bad email":    `{"enabled":true,"recipients":["not-an-email"],"min_severity":"high"}`,
		"bad severity": `{"enabled":true,"recipients":["a@b.co"],"min_severity":"urgent"}`,
		"header inj":   `{"enabled":true,"recipients":["a@b.co\r\nBcc: x@y.z"],"min_severity":"high"}`,
	} {
		if w := e.do("PUT", path, body, true, base); w.Code != 400 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if w := e.do("PUT", path, `{"enabled":true,"recipients":["ops@example.com"],"min_severity":"high"}`, true, base); w.Code != 200 {
		t.Errorf("valid settings: %d %s", w.Code, w.Body)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestSuppressionExpiryRules(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	path := "/api/findings/" + itoa(e.findID)
	patch := func(body string) int { return e.do("PATCH", path, body, true, base).Code }
	const why = `"reason":"reviewed by the security team"`

	// Heuristic finding: a permanent false positive is allowed, risk acceptance must expire.
	if c := patch(`{"status":"accepted_risk",` + why + `}`); c != 400 {
		t.Errorf("accepted_risk without expiry: %d, want 400", c)
	}
	if c := patch(`{"status":"accepted_risk",` + why + `,"expires_in_days":366}`); c != 400 {
		t.Errorf("accepted_risk 366 days: %d, want 400", c)
	}
	if c := patch(`{"status":"accepted_risk",` + why + `,"expires_in_days":-5}`); c != 400 {
		t.Errorf("negative expiry: %d, want 400", c)
	}
	if c := patch(`{"status":"accepted_risk",` + why + `,"expires_in_days":30}`); c != 200 {
		t.Fatalf("accepted_risk 30 days: %d", c)
	}
	var until *time.Time
	_ = e.pool.QueryRow(ctx, `SELECT suppressed_until FROM findings WHERE id=$1`, e.findID).Scan(&until)
	if until == nil || until.Before(time.Now().Add(29*24*time.Hour)) {
		t.Errorf("suppressed_until = %v", until)
	}
	if c := patch(`{"status":"false_positive",` + why + `}`); c != 200 {
		t.Errorf("permanent false positive on a heuristic finding: %d", c)
	}
	// Reopening clears suppression fields.
	if c := patch(`{"status":"open"}`); c != 200 {
		t.Fatalf("reopen: %d", c)
	}
	var reason *string
	_ = e.pool.QueryRow(ctx, `SELECT suppressed_until, suppression_reason FROM findings WHERE id=$1`, e.findID).Scan(&until, &reason)
	if until != nil || reason != nil {
		t.Errorf("suppression fields not cleared: %v %v", until, reason)
	}

	// Confirmed signature matches can never be suppressed without an expiry of at most 90 days.
	_, err := e.pool.Exec(ctx, `UPDATE findings SET confidence='confirmed_signature' WHERE id=$1`, e.findID)
	if err != nil {
		t.Fatal(err)
	}
	if c := patch(`{"status":"false_positive",` + why + `}`); c != 400 {
		t.Errorf("signature suppression without expiry: %d, want 400", c)
	}
	if c := patch(`{"status":"false_positive",` + why + `,"expires_in_days":91}`); c != 400 {
		t.Errorf("signature suppression 91 days: %d, want 400", c)
	}
	if c := patch(`{"status":"false_positive",` + why + `,"expires_in_days":90}`); c != 200 {
		t.Errorf("signature suppression 90 days: %d", c)
	}
}
