package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type NotifyScan struct {
	ScanID, InstallationID, RepositoryID int64
	RepoName, Branch, Commit, Author     string
	PRNumber                             int
	CreatedAt                            time.Time
}

type NotifyFinding struct {
	ID                         int64
	RuleID, Title, Category    string
	Severity, Confidence, Path string
	Line                       int
}

func (s *Store) NotifyScan(ctx context.Context, scanID int64) (NotifyScan, error) {
	var n NotifyScan
	err := s.Pool.QueryRow(ctx, `SELECT s.id, s.installation_id, s.repository_id, r.full_name, COALESCE(s.branch,''), s.commit_sha,
		COALESCE(s.author,''), COALESCE(s.pr_number,0), s.created_at
		FROM scans s JOIN repositories r ON r.id=s.repository_id AND r.installation_id=s.installation_id WHERE s.id=$1`, scanID).
		Scan(&n.ScanID, &n.InstallationID, &n.RepositoryID, &n.RepoName, &n.Branch, &n.Commit, &n.Author, &n.PRNumber, &n.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return n, ErrNotFound
	}
	return n, err
}

// UnnotifiedFindings returns open, not-yet-alerted findings seen in scanID.
func (s *Store) UnnotifiedFindings(ctx context.Context, scanID int64) ([]NotifyFinding, error) {
	rows, err := s.Pool.Query(ctx, `SELECT f.id, f.rule_id, f.title, f.category, f.severity, f.confidence, f.path, COALESCE(o.line_start,0)
		FROM finding_occurrences o JOIN findings f ON f.id=o.finding_id
		WHERE o.scan_id=$1 AND f.notified_at IS NULL AND f.status='open'
		  AND f.category <> 'vulnerable_dependency' -- routine advisories stay in the dashboard; malicious packages still alert
		ORDER BY f.id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NotifyFinding
	for rows.Next() {
		var f NotifyFinding
		if err := rows.Scan(&f.ID, &f.RuleID, &f.Title, &f.Category, &f.Severity, &f.Confidence, &f.Path, &f.Line); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) MarkNotified(ctx context.Context, ids []int64) error {
	_, err := s.Pool.Exec(ctx, `UPDATE findings SET notified_at=now() WHERE id = ANY($1)`, ids)
	return err
}

type NotifySettings struct {
	Enabled     bool
	Recipients  []string
	MinSeverity string
	Configured  bool
}

func (s *Store) NotifySettings(ctx context.Context, installationID int64) (NotifySettings, error) {
	var n NotifySettings
	err := s.Pool.QueryRow(ctx, `SELECT enabled, recipients, min_severity FROM notification_settings WHERE installation_id=$1`, installationID).
		Scan(&n.Enabled, &n.Recipients, &n.MinSeverity)
	if errors.Is(err, pgx.ErrNoRows) {
		return NotifySettings{}, nil
	}
	n.Configured = err == nil
	return n, err
}

func (s *Store) EnsureNotification(ctx context.Context, installationID, scanID int64, kind string) (int64, error) {
	var id int64
	err := s.Pool.QueryRow(ctx, `INSERT INTO notifications(installation_id, scan_id, kind) VALUES ($1,$2,$3)
		ON CONFLICT (scan_id, kind) DO UPDATE SET kind=EXCLUDED.kind RETURNING id`, installationID, scanID, kind).Scan(&id)
	return id, err
}

// DeliveryStatus returns the status for a recipient, creating a pending row.
func (s *Store) DeliveryStatus(ctx context.Context, notificationID int64, recipient string) (string, error) {
	var st string
	err := s.Pool.QueryRow(ctx, `INSERT INTO notification_deliveries(notification_id, recipient) VALUES ($1,$2)
		ON CONFLICT (notification_id, recipient) DO UPDATE SET recipient=EXCLUDED.recipient RETURNING status`, notificationID, recipient).Scan(&st)
	return st, err
}

func (s *Store) RecordDelivery(ctx context.Context, notificationID int64, recipient, status, providerID, errMsg string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE notification_deliveries SET status=$3, provider_id=NULLIF($4,''), last_error=NULLIF($5,''),
		attempts=attempts+1, sent_at = CASE WHEN $3='sent' THEN now() ELSE sent_at END
		WHERE notification_id=$1 AND recipient=$2`, notificationID, recipient, status, providerID, errMsg)
	return err
}
