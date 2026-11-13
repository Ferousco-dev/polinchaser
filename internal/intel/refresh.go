package intel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const MinRefreshInterval = 15 * time.Minute

type Refresher struct {
	Pool     *pgxpool.Pool
	URLs     []string
	Client   *http.Client
	Interval time.Duration // 0 disables the loop
	Log      *slog.Logger
}

// Run refreshes immediately, then on every Interval, until ctx is cancelled.
func (r *Refresher) Run(ctx context.Context) {
	if len(r.URLs) == 0 || r.Interval <= 0 {
		// Still apply removals: feeds the operator dropped from config stop applying.
		r.syncRemoved(ctx)
		r.Log.Info("threat-intel refresh disabled (no feeds configured or interval off)")
		return
	}
	r.Log.Info("threat-intel refresh enabled", "feeds", len(r.URLs), "interval", r.Interval.String())
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		r.RefreshAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// syncRemoved disables feeds that are no longer configured and updates the rule state.
func (r *Refresher) syncRemoved(ctx context.Context) {
	if _, err := r.Pool.Exec(ctx, `UPDATE intel_feeds SET enabled = COALESCE(url = ANY($1::text[]), FALSE)`, append([]string{}, r.URLs...)); err != nil {
		r.Log.Error("intel: sync enabled feeds", "err", err)
		return
	}
	if err := r.recomputeHash(ctx); err != nil {
		r.Log.Error("intel: recompute state", "err", err)
	}
}

// RefreshAll refreshes every configured feed and disables feeds that are no
// longer configured. Per-feed errors are recorded and logged, never fatal.
func (r *Refresher) RefreshAll(ctx context.Context) {
	if _, err := r.Pool.Exec(ctx, `UPDATE intel_feeds SET enabled = COALESCE(url = ANY($1::text[]), FALSE)`, append([]string{}, r.URLs...)); err != nil {
		r.Log.Error("intel: sync enabled feeds", "err", err)
		return
	}
	for _, u := range r.URLs {
		if err := r.RefreshOne(ctx, u); err != nil {
			r.Log.Warn("intel: feed refresh failed; keeping previous signatures", "feed", hostOf(u), "err", err)
		}
	}
	if err := r.recomputeHash(ctx); err != nil {
		r.Log.Error("intel: recompute state", "err", err)
	}
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return "unknown"
}

// RefreshOne fetches one feed. On any failure the stored signatures are untouched.
func (r *Refresher) RefreshOne(ctx context.Context, feedURL string) error {
	var id int64
	var etag string
	if err := r.Pool.QueryRow(ctx, `INSERT INTO intel_feeds (url, name) VALUES ($1,$2)
		ON CONFLICT (url) DO UPDATE SET enabled = TRUE RETURNING id, etag`, feedURL, hostOf(feedURL)).Scan(&id, &etag); err != nil {
		return err
	}
	record := func(status, msg string) {
		_, _ = r.Pool.Exec(ctx, `UPDATE intel_feeds SET last_fetched_at=now(), last_status=$2, last_error=$3,
			last_ok_at = CASE WHEN $2 IN ('ok','not_modified') THEN now() ELSE last_ok_at END WHERE id=$1`, id, status, truncate(msg, 300))
	}
	body, newETag, err := fetch(ctx, r.Client, feedURL, etag)
	if errors.Is(err, errNotModified) {
		record("not_modified", "")
		return nil
	}
	if err != nil {
		record("error", err.Error())
		return err
	}
	feed, err := ParseFeed(body)
	if err != nil {
		record("error", err.Error())
		return err
	}
	sum := sha256.Sum256(body)
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `DELETE FROM intel_signatures WHERE feed_id=$1`, id); err != nil {
		return err
	}
	for _, s := range feed.Signatures {
		kind, val := "substring", s.Substring
		if s.SHA256 != "" {
			kind, val = "sha256", s.SHA256
		}
		if _, err := tx.Exec(ctx, `INSERT INTO intel_signatures (feed_id, sig_id, family, kind, value, severity, provenance) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			id, s.ID, s.Family, kind, val, s.Severity, s.Provenance); err != nil {
			return fmt.Errorf("store signature %s: %w", s.ID, err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE intel_feeds SET name=$2, license=$3, etag=$4, content_sha256=$5, signature_count=$6,
		last_fetched_at=now(), last_ok_at=now(), last_status='ok', last_error='' WHERE id=$1`,
		id, feed.Name, feed.License, newETag, hex.EncodeToString(sum[:]), len(feed.Signatures)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// recomputeHash stores a digest of the active external signature set.
func (r *Refresher) recomputeHash(ctx context.Context) error {
	h, err := activeHash(ctx, r.Pool)
	if err != nil {
		return err
	}
	_, err = r.Pool.Exec(ctx, `UPDATE intel_state SET hash=$1, updated_at=now() WHERE id=1 AND hash <> $1`, h)
	return err
}

func activeHash(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) (string, error) {
	rows, err := q.Query(ctx, `SELECT f.id, s.sig_id, s.kind, s.value, s.severity
		FROM intel_signatures s JOIN intel_feeds f ON f.id = s.feed_id WHERE f.enabled ORDER BY f.id, s.sig_id`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	h := sha256.New()
	n := 0
	for rows.Next() {
		var fid int64
		var a, b, c, d string
		if err := rows.Scan(&fid, &a, &b, &c, &d); err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%d\x00%s\x00%s\x00%s\x00%s\n", fid, a, b, c, d)
		n++
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
