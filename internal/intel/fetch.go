package intel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

var errNotModified = errors.New("not modified")

// NewHTTPClient returns a client that refuses private, loopback and link-local
// addresses (checked at dial time, so DNS rebinding cannot bypass it) and only
// follows https redirects. allowPrivate is for tests and local development.
func NewHTTPClient(allowPrivate bool) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if !allowPrivate {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || blocked(ip) {
				return fmt.Errorf("address %s is not allowed", host)
			}
			return nil
		}
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{DialContext: d.DialContext, Proxy: nil, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if !allowPrivate && req.URL.Scheme != "https" {
				return errors.New("redirect to non-https URL refused")
			}
			return nil
		},
	}
}

func blocked(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xC0 == 64 { // 100.64.0.0/10 carrier-grade NAT
		return true
	}
	return false
}

// fetch downloads a feed with a size cap. A 304 returns errNotModified.
func fetch(ctx context.Context, c *http.Client, rawURL, etag string) (body []byte, newETag string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, "", errors.New("invalid feed URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", errors.New("invalid feed URL")
	}
	req.Header.Set("User-Agent", "polinchaser-intel/1")
	req.Header.Set("Accept", "application/json")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.Do(req)
	if err != nil {
		// url.Error embeds the URL; the URL may carry a token, so drop it.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil, etag, errNotModified
	case resp.StatusCode != http.StatusOK:
		return nil, "", fmt.Errorf("feed returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxFeedBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("read feed: %w", err)
	}
	if len(b) > MaxFeedBytes {
		return nil, "", fmt.Errorf("feed larger than %d bytes", MaxFeedBytes)
	}
	return b, resp.Header.Get("ETag"), nil
}
