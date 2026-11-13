// Package dashboard serves the operator dashboard: a JSON API backed only by
// persisted data, plus the embedded static single-page app.
package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Ferousco-dev/polinchaser/internal/auth"
	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

//go:embed web
var webFS embed.FS

// Info is non-secret deployment state shown on the system page.
type Info struct {
	Env              string
	GitHubConfigured bool
	EmailConfigured  bool
	Rules            scanner.RuleSet
}

type Dashboard struct {
	Pool *pgxpool.Pool
	Auth *auth.HTTP
	Info Info
}

func (d *Dashboard) Routes(mux *http.ServeMux) {
	d.Auth.Routes(mux)
	api := func(pattern string, f http.HandlerFunc) {
		mux.Handle(pattern, d.Auth.OriginGuard(d.Auth.Require(f)))
	}
	api("GET /api/overview", d.overview)
	api("GET /api/repositories", d.repositories)
	api("GET /api/scans", d.scans)
	api("GET /api/scans/{id}", d.scan)
	api("GET /api/findings", d.findings)
	api("GET /api/findings/{id}", d.finding)
	api("PATCH /api/findings/{id}", d.updateFinding)
	api("GET /api/system", d.system)
	api("GET /api/intel", d.intel)
	api("GET /api/observability", d.observability)
	api("GET /api/audit", d.audit)
	api("GET /api/installations", d.installations)
	api("PUT /api/installations/{id}/notifications", d.putNotifications)
	mux.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "User-agent: *\nDisallow: /\n")
	})
	sub, _ := fs.Sub(webFS, "web")
	assets := http.FileServer(http.FS(sub))
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", noCache(assets)))
	mux.HandleFunc("GET /favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/favicon.svg"
		noCache(assets).ServeHTTP(w, r)
	})
	index, _ := fs.ReadFile(sub, "index.html")
	spa := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/webhooks/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(index)
	}
	mux.HandleFunc("GET /{path...}", spa)
}

func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		h.ServeHTTP(w, r)
	})
}

func out(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) { out(w, code, map[string]string{"error": msg}) }

// rows runs a fixed SQL statement and returns rows as JSON-friendly maps.
func (d *Dashboard) rows(ctx context.Context, sql string, args ...any) ([]map[string]any, error) {
	r, err := d.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	res, err := pgx.CollectRows(r, pgx.RowToMap)
	if res == nil {
		res = []map[string]any{}
	}
	return res, err
}

func (d *Dashboard) one(ctx context.Context, sql string, args ...any) (map[string]any, error) {
	r, err := d.rows(ctx, sql, args...)
	if err != nil || len(r) == 0 {
		return nil, err
	}
	return r[0], nil
}

func (d *Dashboard) serverErr(w http.ResponseWriter, r *http.Request, err error) {
	d.Auth.Log.Error("dashboard query failed", "path", r.URL.Path, "err", err)
	fail(w, http.StatusInternalServerError, "internal error")
}

func page(r *http.Request) (limit, offset int) {
	limit, offset = 25, 0
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = min(n, 100)
	}
	if n, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && n > 0 {
		offset = n
	}
	return
}

func (d *Dashboard) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stats, err := d.one(ctx, `SELECT
		(SELECT count(*) FROM installations WHERE removed_at IS NULL) AS installations,
		(SELECT count(*) FROM repositories WHERE active) AS repositories,
		(SELECT count(*) FROM scans) AS scans_total,
		(SELECT count(*) FROM scans WHERE created_at > now() - interval '24 hours') AS scans_24h,
		(SELECT count(*) FROM findings WHERE status='open') AS open_findings,
		(SELECT count(*) FROM findings WHERE status='open' AND severity='critical') AS critical_findings,
		(SELECT count(DISTINCT o.commit_sha) FROM finding_occurrences o JOIN findings f ON f.id=o.finding_id
		   WHERE f.severity IN ('critical','high') AND f.status='open') AS commits_with_blocking_findings,
		(SELECT count(*) FROM scans WHERE status IN ('failed','timed_out','incomplete') AND created_at > now() - interval '7 days') AS unverified_scans_7d`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	sev, err := d.rows(ctx, `SELECT severity, count(*) AS count FROM findings WHERE status='open' GROUP BY severity`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	recent, err := d.rows(ctx, scanSelect+` ORDER BY s.created_at DESC LIMIT 8`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	out(w, 200, map[string]any{"stats": stats, "severity": sev, "recent_scans": recent})
}

func (d *Dashboard) repositories(w http.ResponseWriter, r *http.Request) {
	rows, err := d.rows(r.Context(), `SELECT r.id, r.full_name, r.default_branch, r.private, r.archived, i.account_login AS installation,
		ls.status AS last_scan_status, ls.created_at AS last_scan_at, ls.id AS last_scan_id,
		(SELECT count(*) FROM findings f WHERE f.repository_id=r.id AND f.status='open') AS open_findings,
		(SELECT count(*) FROM findings f WHERE f.repository_id=r.id AND f.status='open' AND f.severity IN ('critical','high')) AS blocking_findings
		FROM repositories r JOIN installations i ON i.id=r.installation_id
		LEFT JOIN LATERAL (SELECT id, status, created_at FROM scans s WHERE s.repository_id=r.id ORDER BY created_at DESC LIMIT 1) ls ON true
		WHERE r.active AND i.removed_at IS NULL ORDER BY blocking_findings DESC, r.full_name`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	out(w, 200, rows)
}

const scanSelect = `SELECT s.id, s.repository_id, r.full_name AS repository, s.trigger, s.commit_sha, s.branch, s.pr_number, s.author, s.status,
	s.files_scanned, s.rule_version, s.created_at, s.finished_at,
	(SELECT count(*) FROM finding_occurrences o WHERE o.scan_id=s.id) AS findings
	FROM scans s JOIN repositories r ON r.id=s.repository_id`

var scanStatuses = map[string]bool{"queued": true, "running": true, "clean": true, "findings_detected": true, "incomplete": true, "failed": true, "timed_out": true}

func (d *Dashboard) scans(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, offset := page(r)
	where, args := []string{"true"}, []any{}
	if v := q.Get("status"); v != "" {
		if !scanStatuses[v] {
			fail(w, 400, "invalid status")
			return
		}
		args = append(args, v)
		where = append(where, fmt.Sprintf("s.status=$%d", len(args)))
	}
	if v := q.Get("repo_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			fail(w, 400, "invalid repo_id")
			return
		}
		args = append(args, n)
		where = append(where, fmt.Sprintf("s.repository_id=$%d", len(args)))
	}
	args = append(args, limit, offset)
	rows, err := d.rows(r.Context(), scanSelect+" WHERE "+strings.Join(where, " AND ")+fmt.Sprintf(" ORDER BY s.created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	out(w, 200, rows)
}

func (d *Dashboard) scan(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, 400, "invalid id")
		return
	}
	s, err := d.one(r.Context(), scanSelect+` WHERE s.id=$1`, id)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	if s == nil {
		fail(w, 404, "not found")
		return
	}
	fs, err := d.rows(r.Context(), `SELECT f.id, f.rule_id, f.title, f.category, f.severity, f.confidence, f.status, f.path, o.line_start, o.line_end
		FROM finding_occurrences o JOIN findings f ON f.id=o.finding_id WHERE o.scan_id=$1
		ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.path`, id)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	s["error"] = nil
	if e, _ := d.one(r.Context(), `SELECT error FROM scans WHERE id=$1`, id); e != nil {
		s["error"] = e["error"]
	}
	out(w, 200, map[string]any{"scan": s, "findings": fs})
}

var (
	severities  = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	confidences = map[string]bool{"confirmed_signature": true, "high": true, "medium": true, "low": true}
	fStatuses   = map[string]bool{"open": true, "resolved": true, "false_positive": true, "accepted_risk": true}
)

func (d *Dashboard) findings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, offset := page(r)
	where, args := []string{"true"}, []any{}
	add := func(col, val string, allowed map[string]bool) bool {
		if val == "" {
			return true
		}
		if allowed != nil && !allowed[val] {
			return false
		}
		args = append(args, val)
		where = append(where, fmt.Sprintf("%s=$%d", col, len(args)))
		return true
	}
	if !add("f.severity", q.Get("severity"), severities) || !add("f.confidence", q.Get("confidence"), confidences) ||
		!add("f.status", q.Get("status"), fStatuses) || !add("f.category", q.Get("category"), nil) {
		fail(w, 400, "invalid filter")
		return
	}
	if v := q.Get("repo_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			fail(w, 400, "invalid repo_id")
			return
		}
		args = append(args, n)
		where = append(where, fmt.Sprintf("f.repository_id=$%d", len(args)))
	}
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(v)
		args = append(args, "%"+esc+"%")
		where = append(where, fmt.Sprintf("(f.path ILIKE $%d OR f.title ILIKE $%d OR f.rule_id ILIKE $%d)", len(args), len(args), len(args)))
	}
	args = append(args, limit, offset)
	rows, err := d.rows(r.Context(), `SELECT f.id, f.rule_id, f.title, f.category, f.severity, f.confidence, f.status, f.path, r.full_name AS repository, f.repository_id,
		f.first_detected_at, f.last_detected_at FROM findings f JOIN repositories r ON r.id=f.repository_id WHERE `+strings.Join(where, " AND ")+
		fmt.Sprintf(` ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.last_detected_at DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	out(w, 200, rows)
}

func (d *Dashboard) finding(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, 400, "invalid id")
		return
	}
	f, err := d.one(r.Context(), `SELECT f.id, f.rule_id, f.rule_version, f.title, f.category, f.severity, f.confidence, f.status, f.path, f.explanation, f.remediation,
		f.first_detected_at, f.last_detected_at, f.suppressed_until, f.suppression_reason, f.repository_id, r.full_name AS repository
		FROM findings f JOIN repositories r ON r.id=f.repository_id WHERE f.id=$1`, id)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	if f == nil {
		fail(w, 404, "not found")
		return
	}
	occ, err := d.rows(r.Context(), `SELECT o.scan_id, o.commit_sha, o.line_start, o.line_end, o.evidence, s.created_at, s.branch, s.pr_number
		FROM finding_occurrences o JOIN scans s ON s.id=o.scan_id WHERE o.finding_id=$1 ORDER BY o.id DESC LIMIT 50`, id)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	related, err := d.rows(r.Context(), `SELECT id, title, severity, path FROM findings WHERE repository_id=$1 AND id<>$2 AND status='open' AND (rule_id=$3 OR path=$4) ORDER BY id DESC LIMIT 10`,
		f["repository_id"], id, f["rule_id"], f["path"])
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	out(w, 200, map[string]any{"finding": f, "occurrences": occ, "related": related})
}

func (d *Dashboard) updateFinding(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, 400, "invalid id")
		return
	}
	var in struct {
		Status        string `json:"status"`
		Reason        string `json:"reason"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !fStatuses[in.Status] {
		fail(w, 400, "invalid request")
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	suppress := in.Status == "false_positive" || in.Status == "accepted_risk"
	if suppress && len(in.Reason) < 10 {
		fail(w, 400, "a reason of at least 10 characters is required to suppress a finding")
		return
	}
	if len(in.Reason) > 500 {
		fail(w, 400, "reason too long")
		return
	}
	var confidence string
	if err := d.Pool.QueryRow(r.Context(), `SELECT confidence FROM findings WHERE id=$1`, id).Scan(&confidence); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, 404, "not found")
			return
		}
		d.serverErr(w, r, err)
		return
	}
	// Expiry rules: risk acceptance and any suppression of a confirmed signature
	// match must expire, so known malware or accepted risk cannot be hidden forever.
	maxDays, mustExpire := 365, in.Status == "accepted_risk"
	if confidence == "confirmed_signature" {
		maxDays, mustExpire = 90, true
	}
	var until any
	if suppress {
		if in.ExpiresInDays < 0 || in.ExpiresInDays > maxDays {
			fail(w, 400, fmt.Sprintf("expiry must be between 1 and %d days", maxDays))
			return
		}
		if in.ExpiresInDays == 0 && mustExpire {
			fail(w, 400, fmt.Sprintf("this suppression must expire (choose 1 to %d days)", maxDays))
			return
		}
		if in.ExpiresInDays > 0 {
			until = time.Now().Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour)
		}
	} else {
		in.Reason = ""
	}
	reason := any(nil)
	if suppress {
		reason = in.Reason
	}
	if _, err := d.Pool.Exec(r.Context(), `UPDATE findings SET status=$2, suppressed_until=$3, suppression_reason=$4 WHERE id=$1`, id, in.Status, until, reason); err != nil {
		d.serverErr(w, r, err)
		return
	}
	who, _ := auth.IdentityFrom(r.Context())
	d.writeAudit(r.Context(), "passkey:"+strconv.FormatInt(who.PasskeyID, 10), "finding.status."+in.Status, "finding:"+strconv.FormatInt(id, 10),
		map[string]string{"reason": in.Reason, "expires_in_days": strconv.Itoa(in.ExpiresInDays)})
	out(w, 200, map[string]string{"status": in.Status})
}

func (d *Dashboard) WriteAudit(ctx context.Context, actor, action, target string) {
	d.writeAudit(ctx, actor, action, target, nil)
}

func (d *Dashboard) writeAudit(ctx context.Context, actor, action, target string, detail any) {
	b, _ := json.Marshal(detail)
	if detail == nil {
		b = []byte("{}")
	}
	if _, err := d.Pool.Exec(context.WithoutCancel(ctx), `INSERT INTO audit_logs(actor, action, target, detail) VALUES ($1,$2,$3,$4)`, actor, action, target, b); err != nil {
		d.Auth.Log.Error("audit write failed", "action", action, "err", err)
	}
}

func (d *Dashboard) audit(w http.ResponseWriter, r *http.Request) {
	limit, offset := page(r)
	rows, err := d.rows(r.Context(), `SELECT id, actor, action, target, detail, created_at FROM audit_logs ORDER BY id DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	out(w, 200, rows)
}

func (d *Dashboard) system(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	jobs, err := d.one(ctx, `SELECT
		count(*) FILTER (WHERE state='queued') AS queued, count(*) FILTER (WHERE state='running') AS running,
		count(*) FILTER (WHERE state='dead') AS dead, count(*) FILTER (WHERE state='succeeded' AND finished_at > now() - interval '24 hours') AS succeeded_24h,
		max(updated_at) AS last_activity FROM jobs`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	notif, err := d.one(ctx, `SELECT count(*) FILTER (WHERE status='sent') AS sent, count(*) FILTER (WHERE status='failed') AS failed, count(*) FILTER (WHERE status='pending') AS pending,
		count(*) FILTER (WHERE feedback='bounced') AS bounced, count(*) FILTER (WHERE feedback='complained') AS complained FROM notification_deliveries`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	dead, err := d.rows(ctx, `SELECT id, kind, attempts, last_error, finished_at FROM jobs WHERE state='dead' ORDER BY finished_at DESC NULLS LAST LIMIT 10`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	out(w, 200, map[string]any{"database": "up", "jobs": jobs, "notifications": notif, "dead_jobs": dead,
		"github_app_configured": d.Info.GitHubConfigured, "email_configured": d.Info.EmailConfigured, "environment": d.Info.Env})
}

func (d *Dashboard) intel(w http.ResponseWriter, r *http.Request) {
	type sig struct {
		ID         string `json:"id"`
		Family     string `json:"family"`
		Kind       string `json:"kind"`
		Severity   string `json:"severity"`
		Provenance string `json:"provenance"`
	}
	sigs := []sig{}
	for _, s := range d.Info.Rules.Signatures {
		kind := "substring"
		if s.SHA256 != "" {
			kind = "sha256"
		}
		sigs = append(sigs, sig{s.ID, s.Family, kind, string(s.Severity), s.Provenance})
	}
	feeds, err := d.rows(r.Context(), `SELECT name, split_part(split_part(url, '://', 2), '/', 1) AS host, license, enabled, signature_count,
		last_fetched_at, last_ok_at, last_status, last_error FROM intel_feeds ORDER BY id`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	var state string
	_ = d.Pool.QueryRow(r.Context(), `SELECT hash FROM intel_state WHERE id=1`).Scan(&state)
	note := "No external threat-intelligence feeds are configured. Only the built-in signature set is active."
	if len(feeds) > 0 {
		note = "External feeds are chosen by the operator. Their signatures are exact matches only and are labelled with the feed they came from."
	}
	out(w, 200, map[string]any{"version": d.Info.Rules.Version, "external_hash": state, "signatures": sigs, "feeds": feeds, "note": note})
}

func (d *Dashboard) installations(w http.ResponseWriter, r *http.Request) {
	rows, err := d.rows(r.Context(), `SELECT i.id, i.account_login, i.account_type, i.repository_selection, i.suspended, i.created_at,
		(SELECT count(*) FROM repositories r WHERE r.installation_id=i.id AND r.active) AS repositories,
		COALESCE(n.enabled, true) AS notify_enabled, COALESCE(n.recipients, '{}') AS notify_recipients, COALESCE(n.min_severity, 'high') AS notify_min_severity
		FROM installations i LEFT JOIN notification_settings n ON n.installation_id=i.id WHERE i.removed_at IS NULL ORDER BY i.account_login`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	out(w, 200, rows)
}

func (d *Dashboard) putNotifications(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, 400, "invalid id")
		return
	}
	var in struct {
		Enabled     bool     `json:"enabled"`
		Recipients  []string `json:"recipients"`
		MinSeverity string   `json:"min_severity"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !severities[in.MinSeverity] || len(in.Recipients) > 20 {
		fail(w, 400, "invalid request")
		return
	}
	clean := []string{}
	for _, e := range in.Recipients {
		e = strings.TrimSpace(e)
		a, err := mail.ParseAddress(e)
		if err != nil || a.Address != e || strings.ContainsAny(e, "\r\n<>") {
			fail(w, 400, "invalid email address: "+e)
			return
		}
		clean = append(clean, e)
	}
	tag, err := d.Pool.Exec(r.Context(), `INSERT INTO notification_settings(installation_id, enabled, recipients, min_severity)
		SELECT id,$2,$3,$4 FROM installations WHERE id=$1 AND removed_at IS NULL
		ON CONFLICT (installation_id) DO UPDATE SET enabled=EXCLUDED.enabled, recipients=EXCLUDED.recipients, min_severity=EXCLUDED.min_severity, updated_at=now()`,
		id, in.Enabled, clean, in.MinSeverity)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 404, "not found")
		return
	}
	who, _ := auth.IdentityFrom(r.Context())
	d.writeAudit(r.Context(), "passkey:"+strconv.FormatInt(who.PasskeyID, 10), "settings.notifications", "installation:"+strconv.FormatInt(id, 10), map[string]any{"enabled": in.Enabled, "min_severity": in.MinSeverity, "recipients": len(clean)})
	out(w, 200, map[string]string{"status": "saved"})
}

var _ = errors.New

// observability returns zero-filled daily series for the last N days, all
// computed from persisted rows (no synthetic data).
func (d *Dashboard) observability(w http.ResponseWriter, r *http.Request) {
	days := 14
	if n, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && n >= 7 && n <= 90 {
		days = n
	}
	ctx := r.Context()
	series := func(sql string) ([]map[string]any, error) { return d.rows(ctx, sql, days) }
	scans, err := series(`WITH d AS (SELECT generate_series(date_trunc('day', now()) - ($1::int - 1) * interval '1 day', date_trunc('day', now()), interval '1 day') AS day)
		SELECT to_char(d.day,'YYYY-MM-DD') AS day,
		 count(s.id) FILTER (WHERE s.status='clean') AS clean,
		 count(s.id) FILTER (WHERE s.status='findings_detected') AS findings_detected,
		 count(s.id) FILTER (WHERE s.status IN ('incomplete')) AS incomplete,
		 count(s.id) FILTER (WHERE s.status IN ('failed','timed_out')) AS failed
		FROM d LEFT JOIN scans s ON date_trunc('day', s.created_at)=d.day GROUP BY d.day ORDER BY d.day`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	finds, err := series(`WITH d AS (SELECT generate_series(date_trunc('day', now()) - ($1::int - 1) * interval '1 day', date_trunc('day', now()), interval '1 day') AS day)
		SELECT to_char(d.day,'YYYY-MM-DD') AS day,
		 count(f.id) FILTER (WHERE f.severity='critical') AS critical, count(f.id) FILTER (WHERE f.severity='high') AS high,
		 count(f.id) FILTER (WHERE f.severity='medium') AS medium, count(f.id) FILTER (WHERE f.severity IN ('low','info')) AS low
		FROM d LEFT JOIN findings f ON date_trunc('day', f.first_detected_at)=d.day GROUP BY d.day ORDER BY d.day`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	dur, err := series(`WITH d AS (SELECT generate_series(date_trunc('day', now()) - ($1::int - 1) * interval '1 day', date_trunc('day', now()), interval '1 day') AS day)
		SELECT to_char(d.day,'YYYY-MM-DD') AS day,
		 round((percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM s.finished_at - s.started_at)))::numeric, 2) AS p50,
		 round((percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM s.finished_at - s.started_at)))::numeric, 2) AS p95
		FROM d LEFT JOIN scans s ON date_trunc('day', s.created_at)=d.day AND s.finished_at IS NOT NULL AND s.started_at IS NOT NULL GROUP BY d.day ORDER BY d.day`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	jobs, err := series(`WITH d AS (SELECT generate_series(date_trunc('day', now()) - ($1::int - 1) * interval '1 day', date_trunc('day', now()), interval '1 day') AS day)
		SELECT to_char(d.day,'YYYY-MM-DD') AS day,
		 count(j.id) FILTER (WHERE j.state='succeeded') AS succeeded, count(j.id) FILTER (WHERE j.state='dead') AS dead
		FROM d LEFT JOIN jobs j ON date_trunc('day', j.finished_at)=d.day GROUP BY d.day ORDER BY d.day`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	mail, err := series(`WITH d AS (SELECT generate_series(date_trunc('day', now()) - ($1::int - 1) * interval '1 day', date_trunc('day', now()), interval '1 day') AS day)
		SELECT to_char(d.day,'YYYY-MM-DD') AS day,
		 count(x.id) FILTER (WHERE x.status='sent') AS sent
		FROM d LEFT JOIN notification_deliveries x ON date_trunc('day', x.sent_at)=d.day GROUP BY d.day ORDER BY d.day`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	byRule, err := d.rows(ctx, `SELECT rule_id, count(*) AS count FROM findings WHERE status='open' GROUP BY rule_id ORDER BY count DESC LIMIT 8`)
	if err != nil {
		d.serverErr(w, r, err)
		return
	}
	out(w, 200, map[string]any{"days": days, "scans": scans, "new_findings": finds, "scan_duration_seconds": dur, "jobs": jobs, "emails": mail, "open_by_rule": byRule})
}
