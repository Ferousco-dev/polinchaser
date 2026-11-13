package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

// ResolveHead returns the commit SHA at the tip of branch.
var repoNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9._-]{1,100}$`)

var errBadRepoName = errors.New("invalid repository name")

// ValidRepoName reports whether s looks like a GitHub "owner/repo". Names are
// placed into API URL paths, so anything else (slashes, "..", queries) is refused.
func ValidRepoName(s string) bool {
	if !repoNameRe.MatchString(s) {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func (c *Client) ResolveHead(ctx context.Context, installationID int64, fullName, branch string) (string, error) {
	if !ValidRepoName(fullName) {
		return "", errBadRepoName
	}
	tok, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return "", err
	}
	var out struct {
		SHA string `json:"sha"`
	}
	path := fmt.Sprintf("/repos/%s/commits/%s", fullName, url.PathEscape(branch))
	if err := c.do(ctx, http.MethodGet, path, tok, nil, &out); err != nil {
		return "", err
	}
	return out.SHA, nil
}

// ChangedFiles lists paths changed between base and head. ok=false means the
// list may be incomplete (GitHub caps compare at 300 files) so callers must
// fall back to scanning everything.
func (c *Client) ChangedFiles(ctx context.Context, installationID int64, fullName, base, head string) (paths []string, ok bool, err error) {
	if !ValidRepoName(fullName) {
		return nil, false, errBadRepoName
	}
	tok, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return nil, false, err
	}
	for page := 1; page <= 3; page++ {
		var out struct {
			Files []struct {
				Filename string `json:"filename"`
				Status   string `json:"status"`
			} `json:"files"`
		}
		path := fmt.Sprintf("/repos/%s/compare/%s...%s?per_page=100&page=%d", fullName, url.PathEscape(base), url.PathEscape(head), page)
		if err := c.do(ctx, http.MethodGet, path, tok, nil, &out); err != nil {
			return nil, false, err
		}
		for _, f := range out.Files {
			if f.Status != "removed" {
				paths = append(paths, f.Filename)
			}
		}
		if len(out.Files) < 100 {
			return paths, len(paths) < 300, nil
		}
	}
	return paths, false, nil
}

// FetchSnapshot downloads the repository tarball at sha and unpacks it safely.
// Redirects are restricted to GitHub hosts to prevent SSRF via redirect.
func (c *Client) FetchSnapshot(ctx context.Context, installationID int64, fullName, sha string, lim ArchiveLimits) (scanner.PreparedSource, error) {
	if !ValidRepoName(fullName) {
		return scanner.PreparedSource{}, errBadRepoName
	}
	tok, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return scanner.PreparedSource{}, err
	}
	baseURL, _ := url.Parse(c.base)
	hc := &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return fmt.Errorf("too many redirects")
		}
		if !allowedDownloadHost(req.URL, baseURL) {
			return fmt.Errorf("redirect to disallowed host %q", req.URL.Hostname())
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s/tarball/%s", c.base, fullName, url.PathEscape(sha)), nil)
	if err != nil {
		return scanner.PreparedSource{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "polinchaser")
	resp, err := hc.Do(req)
	if err != nil {
		return scanner.PreparedSource{}, fmt.Errorf("github tarball: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return scanner.PreparedSource{}, &APIError{Status: resp.StatusCode, Path: "tarball"}
	}
	return ExtractTarGz(resp.Body, lim)
}

func allowedDownloadHost(u, base *url.URL) bool {
	h := strings.ToLower(u.Hostname())
	if base != nil && h == strings.ToLower(base.Hostname()) && u.Scheme == base.Scheme {
		return true
	}
	if u.Scheme != "https" {
		return false
	}
	return h == "codeload.github.com" || h == "github.com" || h == "api.github.com" || strings.HasSuffix(h, ".githubusercontent.com")
}

// CheckOutput is the subset of the Checks API output PolinChaser uses.
type CheckOutput struct {
	Title       string       `json:"title"`
	Summary     string       `json:"summary"`
	Text        string       `json:"text,omitempty"`
	Annotations []Annotation `json:"annotations,omitempty"`
}

type Annotation struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Level     string `json:"annotation_level"` // notice | warning | failure
	Title     string `json:"title"`
	Message   string `json:"message"`
}

const CheckName = "PolinChaser Security Scan"

// CreateCheckRun opens an in_progress check on headSHA and returns its id.
func (c *Client) CreateCheckRun(ctx context.Context, installationID int64, fullName, headSHA string) (int64, error) {
	if !ValidRepoName(fullName) {
		return 0, errBadRepoName
	}
	tok, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return 0, err
	}
	var out struct {
		ID int64 `json:"id"`
	}
	err = c.do(ctx, http.MethodPost, "/repos/"+fullName+"/check-runs", tok, map[string]any{
		"name": CheckName, "head_sha": headSHA, "status": "in_progress",
		"output": CheckOutput{Title: "Scan in progress", Summary: "PolinChaser is analysing this commit."},
	}, &out)
	return out.ID, err
}

// CompleteCheckRun finalises the check with a conclusion and output.
func (c *Client) CompleteCheckRun(ctx context.Context, installationID int64, fullName string, checkID int64, conclusion string, out CheckOutput) error {
	if !ValidRepoName(fullName) {
		return errBadRepoName
	}
	tok, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return err
	}
	if len(out.Annotations) > 50 { // API limit per request
		out.Annotations = out.Annotations[:50]
	}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/check-runs/%d", fullName, checkID), tok, map[string]any{
		"status": "completed", "conclusion": conclusion, "output": out,
	}, nil)
}
