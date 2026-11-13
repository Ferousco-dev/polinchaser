// Package webhook authenticates GitHub webhooks, deduplicates deliveries,
// updates installation state and enqueues scan jobs. It never scans inline.
package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Ferousco-dev/polinchaser/internal/github"
	"github.com/Ferousco-dev/polinchaser/internal/queue"
	"github.com/Ferousco-dev/polinchaser/internal/store"
)

const maxBody = 25 << 20 // GitHub's documented maximum payload

const KindScan = "scan"

// ScanJob is the queue payload. CommitSHA empty means "resolve the default
// branch head" (used by installation scans).
type ScanJob struct {
	InstallationID int64  `json:"installation_id"` // internal id
	RepositoryID   int64  `json:"repository_id"`   // internal id
	Trigger        string `json:"trigger"`
	CommitSHA      string `json:"commit_sha,omitempty"`
	BaseSHA        string `json:"base_sha,omitempty"`
	Branch         string `json:"branch,omitempty"`
	PRNumber       int    `json:"pr_number,omitempty"`
	Author         string `json:"author,omitempty"` // Git/GitHub display name; informational only
}

type Handler struct {
	Secret string
	Store  *store.Store
	Queue  *queue.Queue
	Log    *slog.Logger
}

type repoPayload struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
}

type payload struct {
	Action       string `json:"action"`
	Installation struct {
		ID      int64 `json:"id"`
		Account struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"account"`
		RepositorySelection string     `json:"repository_selection"`
		SuspendedAt         *time.Time `json:"suspended_at"`
	} `json:"installation"`
	Repository          *repoPayload  `json:"repository"`
	Repositories        []repoPayload `json:"repositories"`
	RepositoriesAdded   []repoPayload `json:"repositories_added"`
	RepositoriesRemoved []repoPayload `json:"repositories_removed"`
	RepositorySelection string        `json:"repository_selection"`
	Ref                 string        `json:"ref"`
	After               string        `json:"after"`
	Before              string        `json:"before"`
	Deleted             bool          `json:"deleted"`
	Number              int           `json:"number"`
	HeadCommit          *struct {
		Author struct {
			Name string `json:"name"`
		} `json:"author"`
	} `json:"head_commit"`
	PullRequest *struct {
		User struct {
			Login string `json:"login"`
		} `json:"user"`
		Head struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
		Base struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Read the RAW body: the signature covers the exact bytes sent.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "payload too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	if !github.VerifySignature(h.Secret, body, r.Header.Get("X-Hub-Signature-256")) {
		h.Log.Warn("webhook signature rejected", "remote", r.RemoteAddr)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	delivery, event := r.Header.Get("X-GitHub-Delivery"), r.Header.Get("X-GitHub-Event")
	if delivery == "" || event == "" || len(delivery) > 100 {
		http.Error(w, "missing delivery headers", http.StatusBadRequest)
		return
	}
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	log := h.Log.With("delivery_id", delivery, "event", event, "action", p.Action)
	ctx := r.Context()

	first, err := h.Store.ClaimDelivery(ctx, delivery, event, p.Action)
	if err != nil {
		log.Error("claim delivery", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !first {
		log.Info("duplicate delivery ignored")
		writeJSON(w, http.StatusOK, "duplicate")
		return
	}
	status, err := h.dispatch(ctx, delivery, event, &p)
	if err != nil {
		// Release so GitHub's redelivery is processed rather than skipped.
		_ = h.Store.ReleaseDelivery(context.WithoutCancel(ctx), delivery)
		log.Error("webhook processing failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	log.Info("webhook processed", "result", status)
	writeJSON(w, http.StatusAccepted, status)
}

func writeJSON(w http.ResponseWriter, code int, status string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
}

func (h *Handler) dispatch(ctx context.Context, delivery, event string, p *payload) (string, error) {
	switch event {
	case "ping":
		return "pong", nil
	case "installation":
		return h.installation(ctx, delivery, p)
	case "installation_repositories":
		return h.installationRepos(ctx, delivery, p)
	case "push":
		return h.push(ctx, delivery, p)
	case "pull_request":
		return h.pullRequest(ctx, delivery, p)
	}
	return "ignored", nil
}

func (h *Handler) installation(ctx context.Context, delivery string, p *payload) (string, error) {
	gid := p.Installation.ID
	if gid == 0 {
		return "", errors.New("installation event without id")
	}
	switch p.Action {
	case "created", "unsuspend", "new_permissions_accepted":
		id, err := h.Store.UpsertInstallation(ctx, store.Installation{
			GitHubID: gid, AccountID: p.Installation.Account.ID, Login: p.Installation.Account.Login,
			Type: p.Installation.Account.Type, Selection: normSelection(p.Installation.RepositorySelection),
			Suspended: p.Installation.SuspendedAt != nil,
		})
		if err != nil {
			return "", err
		}
		if p.Action == "created" {
			if err := h.registerAndScan(ctx, id, p.Repositories); err != nil {
				return "", err
			}
		}
		return "installation_registered", nil
	case "deleted":
		return "installation_removed", h.Store.RemoveInstallation(ctx, gid)
	case "suspend":
		return "installation_suspended", h.Store.SetSuspended(ctx, gid, true)
	}
	return "ignored", nil
}

func (h *Handler) installationRepos(ctx context.Context, delivery string, p *payload) (string, error) {
	id, err := h.Store.InstallationID(ctx, p.Installation.ID)
	if errors.Is(err, store.ErrNotFound) {
		return "ignored_unknown_installation", nil
	}
	if err != nil {
		return "", err
	}
	if p.RepositorySelection != "" {
		if err := h.Store.SetSelection(ctx, p.Installation.ID, p.RepositorySelection); err != nil {
			return "", err
		}
	}
	if err := h.registerAndScan(ctx, id, p.RepositoriesAdded); err != nil {
		return "", err
	}
	for _, r := range p.RepositoriesRemoved {
		if err := h.Store.DeactivateRepo(ctx, id, r.ID); err != nil {
			return "", err
		}
	}
	return "repositories_updated", nil
}

func (h *Handler) registerAndScan(ctx context.Context, installationID int64, repos []repoPayload) error {
	for _, rp := range repos {
		if !github.ValidRepoName(rp.FullName) {
			h.Log.Warn("ignoring repository with unexpected name", "github_repo_id", rp.ID)
			continue
		}
		repo, err := h.Store.UpsertRepo(ctx, installationID, store.RepoInput{GitHubID: rp.ID, FullName: rp.FullName, DefaultBranch: rp.DefaultBranch, Private: rp.Private, Archived: rp.Archived})
		if err != nil {
			return err
		}
		if _, _, err := h.Queue.Enqueue(ctx, KindScan, ScanJob{InstallationID: installationID, RepositoryID: repo.ID, Trigger: "install"},
			queue.EnqueueOpts{DedupeKey: fmt.Sprintf("install:%d:%d", installationID, repo.ID)}); err != nil {
			return err
		}
	}
	return nil
}

// repoFor validates that the repository in the payload belongs to the
// installation named in the payload. Unknown installs/repos are ignored.
func (h *Handler) repoFor(ctx context.Context, p *payload) (store.Repo, string, error) {
	if p.Repository == nil || p.Installation.ID == 0 {
		return store.Repo{}, "ignored_missing_identity", nil
	}
	instID, err := h.Store.InstallationID(ctx, p.Installation.ID)
	if errors.Is(err, store.ErrNotFound) {
		return store.Repo{}, "ignored_unknown_installation", nil
	}
	if err != nil {
		return store.Repo{}, "", err
	}
	repo, err := h.Store.ActiveRepo(ctx, instID, p.Repository.ID)
	if errors.Is(err, store.ErrNotFound) {
		return store.Repo{}, "ignored_unknown_repository", nil
	}
	return repo, "", err
}

func (h *Handler) push(ctx context.Context, delivery string, p *payload) (string, error) {
	branch, ok := strings.CutPrefix(p.Ref, "refs/heads/")
	if !ok {
		return "ignored_not_branch", nil
	}
	if p.Deleted || strings.Trim(p.After, "0") == "" {
		return "ignored_branch_deleted", nil
	}
	repo, why, err := h.repoFor(ctx, p)
	if err != nil || why != "" {
		return why, err
	}
	_, _, err = h.Queue.Enqueue(ctx, KindScan, ScanJob{
		InstallationID: repo.InstallationID, RepositoryID: repo.ID, Trigger: "push",
		CommitSHA: p.After, BaseSHA: p.Before, Branch: branch, Author: headAuthor(p),
	}, queue.EnqueueOpts{DedupeKey: fmt.Sprintf("push:%d:%s", repo.ID, p.After)})
	return "scan_queued", err
}

func (h *Handler) pullRequest(ctx context.Context, delivery string, p *payload) (string, error) {
	switch p.Action {
	case "opened", "synchronize", "reopened":
	default:
		return "ignored_action", nil
	}
	if p.PullRequest == nil || p.PullRequest.Head.SHA == "" {
		return "ignored_missing_pr", nil
	}
	repo, why, err := h.repoFor(ctx, p)
	if err != nil || why != "" {
		return why, err
	}
	pr := p.PullRequest
	_, _, err = h.Queue.Enqueue(ctx, KindScan, ScanJob{
		InstallationID: repo.InstallationID, RepositoryID: repo.ID, Trigger: "pull_request",
		CommitSHA: pr.Head.SHA, BaseSHA: pr.Base.SHA, Branch: pr.Head.Ref, PRNumber: p.Number, Author: pr.User.Login,
	}, queue.EnqueueOpts{DedupeKey: fmt.Sprintf("pr:%d:%d:%s", repo.ID, p.Number, pr.Head.SHA)})
	return "scan_queued", err
}

func normSelection(s string) string {
	if s == "all" {
		return "all"
	}
	return "selected"
}

func headAuthor(p *payload) string {
	if p.HeadCommit == nil {
		return ""
	}
	return p.HeadCommit.Author.Name
}
