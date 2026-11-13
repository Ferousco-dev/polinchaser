// Package config loads and validates environment configuration. Every
// integration is optional at startup so an operator can bring services up
// incrementally, but each feature reports exactly what is missing.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL string
	ListenAddr  string
	BaseURL     string // public URL used in emails and links
	Env         string // "production" or "development"
	LogLevel    string

	GitHubAppID         int64
	GitHubPrivateKeyPEM []byte
	GitHubWebhookSecret string
	GitHubAPIBase       string

	ResendAPIKey  string
	EmailFrom     string
	ResendAPIBase string
	// ResendWebhookSecret verifies delivery events (bounces, complaints). Optional.
	ResendWebhookSecret string
	NotifyRecipients    []string
	NotifyMinSeverity   string

	SessionSecret string
	// AdminSetupToken gates registering the very first passkey. Empty disables setup.
	AdminSetupToken string
	// TrustedProxyHops is how many reverse proxies append to X-Forwarded-For.
	TrustedProxyHops int

	WorkerConcurrency int
	// ScheduleInterval is how often each repository is rescanned. 0 disables scheduled scans.
	ScheduleInterval time.Duration
	// IntelFeedURLs are operator-chosen threat-intel feeds (none by default).
	IntelFeedURLs []string
	// OSVEnabled turns on dependency advisory lookups. It sends package names and versions to OSV.
	OSVEnabled bool
	OSVAPIBase string
	// RetentionScanDays / RetentionAuditDays: how long scans and audit rows are kept. 0 keeps forever.
	RetentionScanDays  int
	RetentionAuditDays int
	// IntelRefreshInterval is how often feeds are re-fetched. 0 disables refresh.
	IntelRefreshInterval time.Duration
	JobLease             time.Duration
	ScanTimeout          time.Duration
}

// Secret fields that must never be logged.
func (c Config) String() string {
	return fmt.Sprintf("Config{env=%s listen=%s base=%s github_app=%d resend=%t workers=%d}",
		c.Env, c.ListenAddr, c.BaseURL, c.GitHubAppID, c.ResendAPIKey != "", c.WorkerConcurrency)
}

// Load reads configuration through getenv and returns all problems at once.
func Load(getenv func(string) string) (Config, error) {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	str := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	num := func(k string, def int) int {
		v := strings.TrimSpace(getenv(k))
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			bad("%s must be a positive integer", k)
			return def
		}
		return n
	}
	dur := func(k string, def time.Duration) time.Duration {
		v := strings.TrimSpace(getenv(k))
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			bad("%s must be a positive duration like 5m", k)
			return def
		}
		return d
	}

	c := Config{
		DatabaseURL:         str("DATABASE_URL", ""),
		ListenAddr:          ":" + str("PORT", "8080"),
		BaseURL:             strings.TrimRight(str("BASE_URL", ""), "/"),
		Env:                 str("APP_ENV", "development"),
		LogLevel:            str("LOG_LEVEL", "info"),
		GitHubWebhookSecret: str("GITHUB_WEBHOOK_SECRET", ""),
		GitHubAPIBase:       strings.TrimRight(str("GITHUB_API_BASE", "https://api.github.com"), "/"),
		ResendAPIKey:        str("RESEND_API_KEY", ""),
		EmailFrom:           str("EMAIL_FROM", ""),
		ResendAPIBase:       str("RESEND_API_BASE", ""),
		NotifyMinSeverity:   str("NOTIFY_MIN_SEVERITY", "high"),
		SessionSecret:       str("SESSION_SECRET", ""),
		AdminSetupToken:     str("ADMIN_SETUP_TOKEN", ""),
		TrustedProxyHops:    num("TRUSTED_PROXY_HOPS", 1),
		WorkerConcurrency:   num("WORKER_CONCURRENCY", 2),
		JobLease:            dur("JOB_LEASE", 5*time.Minute),
		ScanTimeout:         dur("SCAN_TIMEOUT", 10*time.Minute),
	}
	if c.Env != "production" && c.Env != "development" {
		bad("APP_ENV must be production or development")
	}
	if c.DatabaseURL == "" {
		bad("DATABASE_URL is required")
	}
	if c.BaseURL != "" {
		if u, err := url.Parse(c.BaseURL); err != nil || u.Host == "" || (u.Scheme != "https" && !(c.Env == "development" && u.Scheme == "http")) {
			bad("BASE_URL must be an https URL (http allowed only in development)")
		}
	} else if c.Env == "production" {
		bad("BASE_URL is required in production")
	}
	switch v := strings.ToLower(strings.TrimSpace(getenv("SCHEDULE_INTERVAL"))); v {
	case "":
		c.ScheduleInterval = 24 * time.Hour
	case "off", "0":
		c.ScheduleInterval = 0
	default:
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Hour {
			bad("SCHEDULE_INTERVAL must be \"off\" or a duration of at least 1h, like 24h")
		} else {
			c.ScheduleInterval = d
		}
	}
	for _, raw := range strings.Split(getenv("INTEL_FEED_URLS"), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(c.Env == "development" && u.Scheme == "http")) {
			bad("INTEL_FEED_URLS entries must be https URLs without credentials in the URL")
			continue
		}
		c.IntelFeedURLs = append(c.IntelFeedURLs, raw)
	}
	if len(c.IntelFeedURLs) > 10 {
		bad("INTEL_FEED_URLS allows at most 10 feeds")
	}
	switch v := strings.ToLower(strings.TrimSpace(getenv("INTEL_REFRESH_INTERVAL"))); v {
	case "":
		c.IntelRefreshInterval = 6 * time.Hour
	case "off", "0":
		c.IntelRefreshInterval = 0
	default:
		d, err := time.ParseDuration(v)
		if err != nil || d < 15*time.Minute {
			bad("INTEL_REFRESH_INTERVAL must be \"off\" or a duration of at least 15m, like 6h")
		} else {
			c.IntelRefreshInterval = d
		}
	}
	days := func(key string, def int) int {
		v := strings.ToLower(strings.TrimSpace(getenv(key)))
		switch v {
		case "":
			return def
		case "off", "0":
			return 0
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 30 || n > 3650 {
			bad("%s must be \"off\" or a number of days between 30 and 3650", key)
			return def
		}
		return n
	}
	c.RetentionScanDays = days("RETENTION_SCAN_DAYS", 180)
	c.RetentionAuditDays = days("RETENTION_AUDIT_DAYS", 365)
	switch strings.ToLower(strings.TrimSpace(getenv("OSV_ENABLED"))) {
	case "", "false", "0", "no":
	case "true", "1", "yes":
		c.OSVEnabled = true
	default:
		bad("OSV_ENABLED must be true or false")
	}
	c.OSVAPIBase = strings.TrimRight(strings.TrimSpace(getenv("OSV_API_BASE")), "/")
	if c.OSVAPIBase != "" {
		u, err := url.Parse(c.OSVAPIBase)
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(c.Env == "development" && u.Scheme == "http")) {
			bad("OSV_API_BASE must be an https URL")
		}
	}
	c.ResendWebhookSecret = strings.TrimSpace(getenv("RESEND_WEBHOOK_SECRET"))
	if c.ResendWebhookSecret != "" {
		if !validWebhookSecret(c.ResendWebhookSecret) {
			bad("RESEND_WEBHOOK_SECRET must be the whsec_ signing secret from Resend")
		}
	}
	if c.SessionSecret != "" && len(c.SessionSecret) < 32 {
		bad("SESSION_SECRET must be at least 32 characters")
	}
	if c.AdminSetupToken != "" && len(c.AdminSetupToken) < 32 {
		bad("ADMIN_SETUP_TOKEN must be at least 32 characters")
	}
	if c.TrustedProxyHops < 0 || c.TrustedProxyHops > 5 {
		bad("TRUSTED_PROXY_HOPS must be between 0 and 5")
	}
	if id := str("GITHUB_APP_ID", ""); id != "" {
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil || n <= 0 {
			bad("GITHUB_APP_ID must be a positive integer")
		}
		c.GitHubAppID = n
		pem, err := decodeKey(getenv("GITHUB_APP_PRIVATE_KEY"))
		if err != nil {
			bad("GITHUB_APP_PRIVATE_KEY: %v", err)
		}
		c.GitHubPrivateKeyPEM = pem
		if c.GitHubWebhookSecret == "" {
			bad("GITHUB_WEBHOOK_SECRET is required when GITHUB_APP_ID is set")
		}
	}
	for _, r := range strings.Split(getenv("NOTIFY_DEFAULT_RECIPIENTS"), ",") {
		if r = strings.TrimSpace(r); r == "" {
			continue
		}
		if !validEmail(r) {
			bad("NOTIFY_DEFAULT_RECIPIENTS contains an invalid address")
			break
		}
		c.NotifyRecipients = append(c.NotifyRecipients, r)
	}
	switch c.NotifyMinSeverity {
	case "critical", "high", "medium", "low", "info":
	default:
		bad("NOTIFY_MIN_SEVERITY must be critical, high, medium, low or info")
	}
	if c.ResendAPIKey != "" && c.EmailFrom == "" {
		bad("EMAIL_FROM is required when RESEND_API_KEY is set")
	}
	return c, errors.Join(errs...)
}

// decodeKey accepts a raw PEM or a base64-encoded PEM (convenient for
// single-line environment variables on hosting platforms).
func decodeKey(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, errors.New("required when GITHUB_APP_ID is set")
	}
	v = strings.ReplaceAll(v, `\n`, "\n")
	if strings.Contains(v, "-----BEGIN") {
		return []byte(v), nil
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || !strings.Contains(string(b), "-----BEGIN") {
		return nil, errors.New("must be a PEM or base64-encoded PEM")
	}
	return b, nil
}

// GitHubEnabled reports whether the GitHub App is fully configured.
func (c Config) GitHubEnabled() bool {
	return c.GitHubAppID != 0 && len(c.GitHubPrivateKeyPEM) > 0 && c.GitHubWebhookSecret != ""
}

// EmailEnabled reports whether Resend is configured.
func (c Config) EmailEnabled() bool { return c.ResendAPIKey != "" && c.EmailFrom != "" }

func validEmail(s string) bool {
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && !strings.ContainsAny(s, "\r\n<>")
}

// validWebhookSecret checks the "whsec_" + base64 shape of a Resend signing secret.
func validWebhookSecret(s string) bool {
	if !strings.HasPrefix(s, "whsec_") {
		return false
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "whsec_"))
	return err == nil && len(key) >= 16
}
