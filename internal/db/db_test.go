package db_test

import (
	"context"
	"testing"

	"github.com/Ferousco-dev/polinchaser/internal/db"
	"github.com/Ferousco-dev/polinchaser/internal/testutil"
)

func TestMigrateIsIdempotent(t *testing.T) {
	pool := testutil.Pool(t) // already migrated once
	applied, err := db.Migrate(context.Background(), pool)
	if err != nil || len(applied) != 0 {
		t.Fatalf("second run should be a no-op: %v %v", applied, err)
	}
}

func TestInstallationDeleteCascades(t *testing.T) {
	pool := testutil.Pool(t)
	ctx := context.Background()
	var inst, repo int64
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(pool.QueryRow(ctx, `INSERT INTO installations(github_installation_id,account_id,account_login,account_type) VALUES (1,1,'a','User') RETURNING id`).Scan(&inst))
	must(pool.QueryRow(ctx, `INSERT INTO repositories(installation_id,github_repo_id,full_name) VALUES ($1,9,'a/b') RETURNING id`, inst).Scan(&repo))
	_, err := pool.Exec(ctx, `INSERT INTO scans(installation_id,repository_id,trigger,commit_sha) VALUES ($1,$2,'push','abc')`, inst, repo)
	must(err)
	_, err = pool.Exec(ctx, `DELETE FROM installations WHERE id=$1`, inst)
	must(err)
	var n int
	must(pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM repositories)+(SELECT count(*) FROM scans)`).Scan(&n))
	if n != 0 {
		t.Fatalf("orphans remain: %d", n)
	}
}

func TestRepoUniquePerInstallation(t *testing.T) {
	pool := testutil.Pool(t)
	ctx := context.Background()
	var inst int64
	_ = pool.QueryRow(ctx, `INSERT INTO installations(github_installation_id,account_id,account_login,account_type) VALUES (1,1,'a','User') RETURNING id`).Scan(&inst)
	_, err := pool.Exec(ctx, `INSERT INTO repositories(installation_id,github_repo_id,full_name) VALUES ($1,9,'a/b')`, inst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO repositories(installation_id,github_repo_id,full_name) VALUES ($1,9,'a/b')`, inst); err == nil {
		t.Fatal("duplicate repo accepted")
	}
}
