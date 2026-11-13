package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxResponseBytes = 32 << 20

// APIError carries the HTTP status so callers can decide on retry.
type APIError struct {
	Status int
	Path   string
	Body   string
}

func (e *APIError) Error() string { return fmt.Sprintf("github api %s: status %d", e.Path, e.Status) }

// Retryable reports whether the same request may succeed later.
func (e *APIError) Retryable() bool { return e.Status == 429 || e.Status >= 500 || e.Status == 403 }

type Client struct {
	appID int64
	key   *rsa.PrivateKey
	base  string
	http  *http.Client
	now   func() time.Time

	mu     sync.Mutex
	tokens map[int64]cachedToken
}

type cachedToken struct {
	value   string
	expires time.Time
}

func NewClient(appID int64, key *rsa.PrivateKey, apiBase string) *Client {
	return &Client{appID: appID, key: key, base: strings.TrimRight(apiBase, "/"),
		http: &http.Client{Timeout: 30 * time.Second}, now: time.Now, tokens: map[int64]cachedToken{}}
}

func (c *Client) do(ctx context.Context, method, path, bearer string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "polinchaser")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("github request %s: %w", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		// Body is kept short and never includes request credentials.
		msg := string(data)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return &APIError{Status: resp.StatusCode, Path: path, Body: msg}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// InstallationToken returns a cached short-lived token, refreshing it one
// minute before expiry. Tokens are held in memory only.
func (c *Client) InstallationToken(ctx context.Context, installationID int64) (string, error) {
	c.mu.Lock()
	t, ok := c.tokens[installationID]
	c.mu.Unlock()
	if ok && c.now().Add(time.Minute).Before(t.expires) {
		return t.value, nil
	}
	jwt, err := AppJWT(c.appID, c.key, c.now())
	if err != nil {
		return "", err
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	path := fmt.Sprintf("/app/installations/%d/access_tokens", installationID)
	if err := c.do(ctx, http.MethodPost, path, jwt, nil, &out); err != nil {
		return "", err
	}
	c.mu.Lock()
	c.tokens[installationID] = cachedToken{out.Token, out.ExpiresAt}
	c.mu.Unlock()
	return out.Token, nil
}

type Repo struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
}

// ListInstallationRepos pages through every repository the installation may access.
func (c *Client) ListInstallationRepos(ctx context.Context, installationID int64) ([]Repo, error) {
	tok, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return nil, err
	}
	var all []Repo
	for page := 1; page <= 200; page++ {
		var out struct {
			Repositories []Repo `json:"repositories"`
		}
		q := url.Values{"per_page": {"100"}, "page": {fmt.Sprint(page)}}
		if err := c.do(ctx, http.MethodGet, "/installation/repositories?"+q.Encode(), tok, nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Repositories...)
		if len(out.Repositories) < 100 {
			return all, nil
		}
	}
	return all, fmt.Errorf("github: too many repositories")
}
