// Package osv looks up known vulnerabilities and malicious-package reports for
// pinned dependencies using the OSV.dev API (https://osv.dev).
//
// Privacy: enabling this sends package names, versions and ecosystems found in
// scanned lockfiles to the OSV service. It never sends repository names, file
// paths, code or tokens. It is off unless the operator turns it on.
//
// OSV data is queried live and only advisory ids, summaries and severities are
// stored in findings, each linking back to osv.dev. OSV records are published under
// open licences (see https://google.github.io/osv.dev/data/); check them before
// redistributing any of it.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

const (
	DefaultBase  = "https://api.osv.dev"
	batchSize    = 500
	maxDetails   = 300 // advisories whose details are fetched per scan
	maxBodyBytes = 4 << 20
	cacheLimit   = 5000
)

type Client struct {
	Base string
	HTTP *http.Client

	mu    sync.Mutex
	cache map[string]scanner.Advisory
}

func New(base string) *Client {
	if base == "" {
		base = DefaultBase
	}
	return &Client{Base: strings.TrimRight(base, "/"), HTTP: &http.Client{Timeout: 20 * time.Second}, cache: map[string]scanner.Advisory{}}
}

type query struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

// Check returns findings for dependencies with matching advisories. On a network or
// API error it returns the findings found so far together with the error; the caller
// must treat the dependency check as incomplete, never as clean.
func (c *Client) Check(ctx context.Context, deps []scanner.Dependency) ([]scanner.Finding, error) {
	type hit struct {
		dep scanner.Dependency
		id  string
	}
	var hits []hit
	var firstErr error
	for start := 0; start < len(deps); start += batchSize {
		end := min(start+batchSize, len(deps))
		chunk := deps[start:end]
		qs := make([]query, len(chunk))
		for i, d := range chunk {
			qs[i].Package.Name, qs[i].Package.Ecosystem, qs[i].Version = d.Name, d.Ecosystem, d.Version
		}
		var resp struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := c.do(ctx, http.MethodPost, "/v1/querybatch", map[string]any{"queries": qs}, &resp); err != nil {
			firstErr = err
			break
		}
		if len(resp.Results) != len(chunk) {
			firstErr = errors.New("osv: response size did not match the query")
			break
		}
		for i, r := range resp.Results {
			for _, v := range r.Vulns {
				if scanner.ValidAdvisoryID(v.ID) {
					hits = append(hits, hit{chunk[i], v.ID})
				}
			}
		}
	}

	ids := map[string]bool{}
	for _, h := range hits {
		ids[h.id] = true
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	adv := map[string]scanner.Advisory{}
	for i, id := range sorted {
		if i >= maxDetails || ctx.Err() != nil {
			adv[id] = scanner.Advisory{ID: id} // severity unknown; still reported
			continue
		}
		a, err := c.detail(ctx, id)
		if err != nil {
			a = scanner.Advisory{ID: id}
		}
		adv[id] = a
	}

	var out []scanner.Finding
	for _, h := range hits {
		if f, ok := scanner.AdvisoryFinding(h.dep, adv[h.id]); ok {
			out = append(out, f)
		}
	}
	return out, firstErr
}

func (c *Client) detail(ctx context.Context, id string) (scanner.Advisory, error) {
	c.mu.Lock()
	a, ok := c.cache[id]
	c.mu.Unlock()
	if ok {
		return a, nil
	}
	var v struct {
		ID               string `json:"id"`
		Summary          string `json:"summary"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, &v); err != nil {
		return scanner.Advisory{}, err
	}
	a = scanner.Advisory{ID: id, Summary: v.Summary, Severity: normSeverity(v.DatabaseSpecific.Severity)}
	c.mu.Lock()
	if len(c.cache) >= cacheLimit {
		c.cache = map[string]scanner.Advisory{}
	}
	c.cache[id] = a
	c.mu.Unlock()
	return a, nil
}

func normSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MODERATE", "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	}
	return ""
}

func (c *Client) do(ctx context.Context, method, path string, body, into any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "polinchaser-osv/1")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("osv request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return fmt.Errorf("osv read: %w", err)
	}
	if len(data) > maxBodyBytes {
		return errors.New("osv response too large")
	}
	return json.Unmarshal(data, into)
}
