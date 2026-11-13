package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

type ScanInput struct {
	InstallationID, RepositoryID int64
	Trigger, CommitSHA, BaseSHA  string
	Branch, Author               string
	PRNumber                     int
	RuleVersion                  string
}

// RepoScoped returns a repository only if it belongs to installationID
// (internal ids). This is the tenant-isolation choke point for worker jobs.
func (s *Store) RepoScoped(ctx context.Context, installationID, repoID int64) (Repo, error) {
	r := Repo{InstallationID: installationID}
	err := s.Pool.QueryRow(ctx, `SELECT id, github_repo_id, full_name, default_branch FROM repositories
		WHERE id=$1 AND installation_id=$2 AND active`, repoID, installationID).
		Scan(&r.ID, &r.GitHubID, &r.FullName, &r.DefaultBranch)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// GitHubInstallationID maps an internal installation id to GitHub's id.
func (s *Store) GitHubInstallationID(ctx context.Context, id int64) (int64, error) {
	var gid int64
	err := s.Pool.QueryRow(ctx, `SELECT github_installation_id FROM installations WHERE id=$1 AND removed_at IS NULL AND NOT suspended`, id).Scan(&gid)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return gid, err
}

func (s *Store) CreateScan(ctx context.Context, in ScanInput) (int64, error) {
	var id int64
	err := s.Pool.QueryRow(ctx, `INSERT INTO scans (installation_id, repository_id, trigger, commit_sha, base_sha, branch, pr_number, rule_version, author, status, started_at)
		VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),NULLIF($7,0),$8,NULLIF($9,''),'running',now()) RETURNING id`,
		in.InstallationID, in.RepositoryID, in.Trigger, in.CommitSHA, in.BaseSHA, in.Branch, in.PRNumber, in.RuleVersion, in.Author).Scan(&id)
	return id, err
}

// FinishScan stores the outcome. errMsg is a short, non-sensitive description.
func (s *Store) FinishScan(ctx context.Context, scanID int64, status scanner.Status, files int, errMsg string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE scans SET status=$2, files_scanned=$3, error=NULLIF($4,''), finished_at=now() WHERE id=$1`,
		scanID, string(status), files, errMsg)
	return err
}

// SaveFindings upserts findings (deduplicated per repository+fingerprint) and
// records an occurrence for this scan, atomically. A previously resolved
// finding that reappears is reopened; false_positive / accepted_risk stay.
func (s *Store) SaveFindings(ctx context.Context, scanID, installationID, repoID int64, commit string, fs []scanner.Finding) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, f := range fs {
		var fid int64
		err := tx.QueryRow(ctx, `
			INSERT INTO findings (installation_id, repository_id, fingerprint, rule_id, rule_version, category, severity, confidence, path, title, explanation, remediation)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (repository_id, fingerprint) DO UPDATE SET
			  last_detected_at=now(), rule_version=EXCLUDED.rule_version, severity=EXCLUDED.severity, confidence=EXCLUDED.confidence,
			  status = CASE WHEN findings.status='resolved' THEN 'open' ELSE findings.status END
			RETURNING id`,
			installationID, repoID, f.Fingerprint, f.RuleID, f.RuleVersion, string(f.Category), string(f.Severity), string(f.Confidence),
			f.Path, f.Title, f.Explanation, f.Remediation).Scan(&fid)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO finding_occurrences (finding_id, scan_id, commit_sha, line_start, line_end, evidence)
			VALUES ($1,$2,$3,NULLIF($4,0),NULLIF($5,0),$6) ON CONFLICT (finding_id, scan_id) DO NOTHING`,
			fid, scanID, commit, f.LineStart, f.LineEnd, f.Evidence); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
