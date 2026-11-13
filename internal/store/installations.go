// Package store holds data-access functions. Every repository lookup is
// scoped by installation so one installation can never read another's data.
package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ Pool *pgxpool.Pool }

type Installation struct {
	GitHubID  int64
	AccountID int64
	Login     string
	Type      string // User | Organization
	Selection string // all | selected
	Suspended bool
}

type RepoInput struct {
	GitHubID      int64
	FullName      string
	DefaultBranch string
	Private       bool
	Archived      bool
}

type Repo struct {
	ID             int64
	InstallationID int64 // internal id
	GitHubID       int64
	FullName       string
	DefaultBranch  string
}

var ErrNotFound = errors.New("store: not found")

// UpsertInstallation creates or revives an installation and returns its internal id.
func (s *Store) UpsertInstallation(ctx context.Context, in Installation) (int64, error) {
	var id int64
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO installations (github_installation_id, account_id, account_login, account_type, repository_selection, suspended)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (github_installation_id) DO UPDATE SET
		  account_login=EXCLUDED.account_login, account_type=EXCLUDED.account_type,
		  repository_selection=EXCLUDED.repository_selection, suspended=EXCLUDED.suspended,
		  removed_at=NULL, updated_at=now()
		RETURNING id`, in.GitHubID, in.AccountID, in.Login, in.Type, in.Selection, in.Suspended).Scan(&id)
	return id, err
}

// InstallationID resolves a GitHub installation id to the internal id.
// Removed installations are treated as unknown.
func (s *Store) InstallationID(ctx context.Context, githubID int64) (int64, error) {
	var id int64
	err := s.Pool.QueryRow(ctx, `SELECT id FROM installations WHERE github_installation_id=$1 AND removed_at IS NULL`, githubID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

// RemoveInstallation soft-removes the installation and deactivates its repos.
func (s *Store) RemoveInstallation(ctx context.Context, githubID int64) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE repositories SET active=false, updated_at=now()
		WHERE installation_id IN (SELECT id FROM installations WHERE github_installation_id=$1)`, githubID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE installations SET removed_at=now(), updated_at=now() WHERE github_installation_id=$1`, githubID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) SetSuspended(ctx context.Context, githubID int64, suspended bool) error {
	_, err := s.Pool.Exec(ctx, `UPDATE installations SET suspended=$2, updated_at=now() WHERE github_installation_id=$1`, githubID, suspended)
	return err
}

func (s *Store) SetSelection(ctx context.Context, githubID int64, selection string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE installations SET repository_selection=$2, updated_at=now() WHERE github_installation_id=$1 AND $2 IN ('all','selected')`, githubID, selection)
	return err
}

// UpsertRepo registers (or reactivates) a repository under an installation.
func (s *Store) UpsertRepo(ctx context.Context, installationID int64, r RepoInput) (Repo, error) {
	if r.DefaultBranch == "" {
		r.DefaultBranch = "main"
	}
	out := Repo{InstallationID: installationID}
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO repositories (installation_id, github_repo_id, full_name, default_branch, private, archived)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (installation_id, github_repo_id) DO UPDATE SET
		  full_name=EXCLUDED.full_name, default_branch=EXCLUDED.default_branch,
		  private=EXCLUDED.private, archived=EXCLUDED.archived, active=true, updated_at=now()
		RETURNING id, github_repo_id, full_name, default_branch`,
		installationID, r.GitHubID, r.FullName, r.DefaultBranch, r.Private, r.Archived).
		Scan(&out.ID, &out.GitHubID, &out.FullName, &out.DefaultBranch)
	return out, err
}

func (s *Store) DeactivateRepo(ctx context.Context, installationID, githubRepoID int64) error {
	_, err := s.Pool.Exec(ctx, `UPDATE repositories SET active=false, updated_at=now() WHERE installation_id=$1 AND github_repo_id=$2`, installationID, githubRepoID)
	return err
}

// ActiveRepo looks a repository up within ONE installation.
func (s *Store) ActiveRepo(ctx context.Context, installationID, githubRepoID int64) (Repo, error) {
	r := Repo{InstallationID: installationID}
	err := s.Pool.QueryRow(ctx, `SELECT id, github_repo_id, full_name, default_branch FROM repositories
		WHERE installation_id=$1 AND github_repo_id=$2 AND active`, installationID, githubRepoID).
		Scan(&r.ID, &r.GitHubID, &r.FullName, &r.DefaultBranch)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// ClaimDelivery records a webhook delivery id. It returns false if the id was
// already recorded (a duplicate or replay).
func (s *Store) ClaimDelivery(ctx context.Context, id, event, action string) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `INSERT INTO webhook_deliveries(delivery_id,event,action) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, id, event, action)
	return tag.RowsAffected() == 1, err
}

// ReleaseDelivery forgets a delivery so GitHub's redelivery can be processed
// after a transient failure.
func (s *Store) ReleaseDelivery(ctx context.Context, id string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM webhook_deliveries WHERE delivery_id=$1`, id)
	return err
}
