// Package worker contains the job handlers run by polinchaser-worker.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/Ferousco-dev/polinchaser/internal/github"
	"github.com/Ferousco-dev/polinchaser/internal/policy"
	"github.com/Ferousco-dev/polinchaser/internal/queue"
	"github.com/Ferousco-dev/polinchaser/internal/store"
	"github.com/Ferousco-dev/polinchaser/internal/webhook"
	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

// Forge is the slice of GitHub the scan handler needs; faked in tests.
type Forge interface {
	ResolveHead(ctx context.Context, installationID int64, fullName, branch string) (string, error)
	ChangedFiles(ctx context.Context, installationID int64, fullName, base, head string) ([]string, bool, error)
	FetchSnapshot(ctx context.Context, installationID int64, fullName, sha string, lim github.ArchiveLimits) (scanner.PreparedSource, error)
	CreateCheckRun(ctx context.Context, installationID int64, fullName, headSHA string) (int64, error)
	CompleteCheckRun(ctx context.Context, installationID int64, fullName string, checkID int64, conclusion string, out github.CheckOutput) error
}

// Enqueuer is satisfied by *queue.Queue.
type Enqueuer interface {
	Enqueue(ctx context.Context, kind string, payload any, o queue.EnqueueOpts) (int64, bool, error)
}

// RuleSource lets the worker pick up refreshed rules between scans.
type RuleSource interface {
	Current(ctx context.Context) (*scanner.Engine, string)
}

// DependencyChecker looks up advisories for pinned dependencies (OSV). Optional.
type DependencyChecker interface {
	Check(ctx context.Context, deps []scanner.Dependency) ([]scanner.Finding, error)
}

type Scanner struct {
	Deps        DependencyChecker // nil disables dependency advisory lookups
	Rules       RuleSource        // optional; overrides Engine and RuleVersion when set
	Notify      Enqueuer          // nil disables alert emails
	Store       *store.Store
	Forge       Forge
	Engine      *scanner.Engine
	RuleVersion string
	Policy      policy.Policy
	Timeout     time.Duration
	Archive     github.ArchiveLimits
	Log         *slog.Logger
}

// contextPaths are always scanned on incremental scans because a change
// elsewhere can make them dangerous (persistence and build/CI configuration).
var contextPrefixes = []string{".vscode/", ".github/workflows/", ".husky/", ".githooks/"}
var contextNames = map[string]bool{"package.json": true, ".npmrc": true, "dockerfile": true, "requirements.txt": true}

func isContext(p string) bool {
	for _, pre := range contextPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return contextNames[strings.ToLower(p)]
}

// Handle is the queue.Handler for "scan" jobs.
func (s *Scanner) Handle(ctx context.Context, j *queue.Job) error {
	var job webhook.ScanJob
	if err := json.Unmarshal(j.Payload, &job); err != nil {
		return queue.Permanent(fmt.Errorf("bad scan payload: %w", err))
	}
	repo, err := s.Store.RepoScoped(ctx, job.InstallationID, job.RepositoryID)
	if errors.Is(err, store.ErrNotFound) {
		return queue.Permanent(errors.New("repository not active under installation"))
	}
	if err != nil {
		return err
	}
	ghInst, err := s.Store.GitHubInstallationID(ctx, job.InstallationID)
	if errors.Is(err, store.ErrNotFound) {
		return queue.Permanent(errors.New("installation removed or suspended"))
	}
	if err != nil {
		return err
	}
	log := s.Log.With("job_id", j.ID, "repo", repo.FullName, "trigger", job.Trigger)
	lastAttempt := j.Attempts >= j.MaxAttempts

	engine, ruleVersion := s.Engine, s.RuleVersion
	if s.Rules != nil {
		engine, ruleVersion = s.Rules.Current(ctx)
	}

	sha := job.CommitSHA
	if sha == "" {
		if sha, err = s.Forge.ResolveHead(ctx, ghInst, repo.FullName, repo.DefaultBranch); err != nil {
			return transient(err)
		}
	}
	scanID, err := s.Store.CreateScan(ctx, store.ScanInput{InstallationID: job.InstallationID, RepositoryID: repo.ID,
		Trigger: job.Trigger, CommitSHA: sha, BaseSHA: job.BaseSHA, Branch: job.Branch, Author: job.Author, PRNumber: job.PRNumber, RuleVersion: ruleVersion})
	if err != nil {
		return err
	}
	log = log.With("scan_id", scanID, "sha", sha)

	checkID, err := s.Forge.CreateCheckRun(ctx, ghInst, repo.FullName, sha)
	if err != nil {
		log.Warn("could not create check run; continuing without it", "err", err)
		checkID = 0
	}
	finish := func(res scanner.Result, errMsg string) error {
		dec := policy.Evaluate(s.Policy, res)
		if checkID != 0 {
			out := github.CheckOutput{Title: dec.Title, Summary: dec.Summary, Annotations: annotations(res.Findings)}
			if err := s.Forge.CompleteCheckRun(ctx, ghInst, repo.FullName, checkID, dec.Conclusion, out); err != nil {
				return transient(fmt.Errorf("complete check run: %w", err))
			}
		}
		if err := s.Store.FinishScan(ctx, scanID, res.Status, res.FilesScanned, errMsg); err != nil {
			return err
		}
		if s.Notify != nil && len(res.Findings) > 0 {
			if _, _, err := s.Notify.Enqueue(ctx, "notify", map[string]int64{"scan_id": scanID}, queue.EnqueueOpts{DedupeKey: fmt.Sprintf("notify:scan:%d", scanID)}); err != nil {
				log.Error("could not enqueue alert", "err", err)
			}
		}
		return nil
	}

	snap, err := s.Forge.FetchSnapshot(ctx, ghInst, repo.FullName, sha, s.Archive)
	if err != nil {
		if isTransient(err) && !lastAttempt {
			_ = s.Store.FinishScan(ctx, scanID, scanner.StatusFailed, 0, "snapshot download failed (will retry)")
			return err
		}
		// Final failure: make the check say "not verified" rather than leaving it pending or clean.
		_ = finish(scanner.Result{Status: scanner.StatusFailed, Error: "snapshot"}, "snapshot download failed")
		return queue.Permanent(fmt.Errorf("fetch snapshot: %w", err))
	}

	incremental := false
	if (job.Trigger == "push" || job.Trigger == "pull_request") && job.BaseSHA != "" && strings.Trim(job.BaseSHA, "0") != "" {
		if changed, ok, err := s.Forge.ChangedFiles(ctx, ghInst, repo.FullName, job.BaseSHA, sha); err == nil && ok {
			keep := map[string]bool{}
			for _, p := range changed {
				keep[p] = true
			}
			for p := range snap.Files {
				if !keep[p] && !isContext(p) {
					delete(snap.Files, p)
				}
			}
			incremental = true
		} else if err != nil {
			log.Warn("compare failed; scanning full snapshot", "err", err)
		}
	}

	scanCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	res := engine.Scan(scanCtx, snap)
	res = s.checkDependencies(scanCtx, snap, res, log)
	log.Info("scan finished", "status", res.Status, "findings", len(res.Findings), "files", res.FilesScanned, "incremental", incremental)

	if len(res.Findings) > 0 {
		if err := s.Store.SaveFindings(ctx, scanID, job.InstallationID, repo.ID, sha, res.Findings); err != nil {
			return err
		}
	}
	return finish(res, res.Error)
}

func annotations(fs []scanner.Finding) []github.Annotation {
	var out []github.Annotation
	for _, f := range fs {
		if f.Severity.Rank() < scanner.SeverityMedium.Rank() || len(out) >= 50 {
			continue
		}
		lvl := "warning"
		if f.Severity.Rank() >= scanner.SeverityHigh.Rank() {
			lvl = "failure"
		}
		start := max(f.LineStart, 1)
		out = append(out, github.Annotation{
			Path: f.Path, StartLine: start, EndLine: max(f.LineEnd, start), Level: lvl,
			Title:   fmt.Sprintf("%s [%s severity, %s confidence]", f.Title, f.Severity, strings.ReplaceAll(string(f.Confidence), "_", " ")),
			Message: f.Explanation + " Rule " + f.RuleID + ".",
		})
	}
	return out
}

func isTransient(err error) bool {
	var ae *github.APIError
	if errors.As(err, &ae) {
		return ae.Retryable()
	}
	return !errors.Is(err, github.ErrArchiveTooLarge)
}

// transient wraps err so permanent GitHub failures dead-letter instead of retrying.
func transient(err error) error {
	if isTransient(err) {
		return err
	}
	return queue.Permanent(err)
}

// checkDependencies adds advisory findings for pinned dependencies. If the lookup fails
// the scan is marked incomplete (never clean), because dependency coverage is missing.
func (s *Scanner) checkDependencies(ctx context.Context, snap scanner.PreparedSource, res scanner.Result, log *slog.Logger) scanner.Result {
	if s.Deps == nil || res.Status == scanner.StatusFailed || res.Status == scanner.StatusTimedOut {
		return res
	}
	paths := make([]string, 0, len(snap.Files))
	for p := range snap.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var deps []scanner.Dependency
	for _, p := range paths {
		deps = append(deps, scanner.ExtractDependencies(p, snap.Files[p])...)
		if len(deps) >= scanner.MaxDependencies {
			deps = deps[:scanner.MaxDependencies]
			break
		}
	}
	if len(deps) == 0 {
		return res
	}
	fs, err := s.Deps.Check(ctx, deps)
	if err != nil {
		log.Warn("dependency lookup failed; marking scan incomplete", "err", err)
		res.Skipped = append(res.Skipped, scanner.Skipped{Path: "(dependency advisories)", Reason: scanner.SkipDepLookup})
	}
	if len(fs) > 0 {
		seen := map[string]bool{}
		for _, f := range res.Findings {
			seen[f.Fingerprint] = true
		}
		for _, f := range fs {
			if !seen[f.Fingerprint] {
				res.Findings = append(res.Findings, f)
			}
		}
		sort.SliceStable(res.Findings, func(i, j int) bool { return res.Findings[i].Severity.Rank() > res.Findings[j].Severity.Rank() })
	}
	if res.Status == scanner.StatusClean {
		switch {
		case len(res.Findings) > 0:
			res.Status = scanner.StatusFindings
		case len(res.Skipped) > 0:
			res.Status = scanner.StatusIncomplete
		}
	}
	return res
}
