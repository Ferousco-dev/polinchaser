package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaultsAndRequired(t *testing.T) {
	if _, err := Load(env(nil)); err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Fatalf("want DATABASE_URL error, got %v", err)
	}
	c, err := Load(env(map[string]string{"DATABASE_URL": "postgres://x"}))
	if err != nil || c.ListenAddr != ":8080" || c.WorkerConcurrency != 2 || c.GitHubEnabled() || c.EmailEnabled() {
		t.Fatalf("bad defaults: %v %v", c, err)
	}
}

func TestProductionRequirements(t *testing.T) {
	_, err := Load(env(map[string]string{"DATABASE_URL": "x", "APP_ENV": "production"}))
	if err == nil || !strings.Contains(err.Error(), "BASE_URL") {
		t.Fatalf("got %v", err)
	}
	_, err = Load(env(map[string]string{"DATABASE_URL": "x", "APP_ENV": "production", "BASE_URL": "http://insecure.example", "SESSION_SECRET": strings.Repeat("s", 32)}))
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http base must be rejected in production: %v", err)
	}
}

func TestGitHubKeyFormats(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
	base := map[string]string{"DATABASE_URL": "x", "GITHUB_APP_ID": "12", "GITHUB_WEBHOOK_SECRET": "s"}
	for name, key := range map[string]string{
		"raw": pem, "escaped": strings.ReplaceAll(pem, "\n", `\n`), "b64": base64.StdEncoding.EncodeToString([]byte(pem)),
	} {
		m := map[string]string{"GITHUB_APP_PRIVATE_KEY": key}
		for k, v := range base {
			m[k] = v
		}
		c, err := Load(env(m))
		if err != nil || !c.GitHubEnabled() {
			t.Errorf("%s: %v", name, err)
		}
	}
	base["GITHUB_APP_PRIVATE_KEY"] = "garbage"
	if _, err := Load(env(base)); err == nil {
		t.Fatal("garbage key accepted")
	}
}

func TestStringRedactsSecrets(t *testing.T) {
	c := Config{ResendAPIKey: "re_supersecret", SessionSecret: "sess", GitHubWebhookSecret: "whsec", DatabaseURL: "postgres://u:pw@h/db"}
	s := c.String()
	for _, leak := range []string{"re_supersecret", "sess", "whsec", "pw"} {
		if strings.Contains(s, leak) {
			t.Fatalf("leaked %q in %s", leak, s)
		}
	}
}

func TestScheduleInterval(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "x"}
	with := func(v string) (Config, error) {
		m := map[string]string{"DATABASE_URL": "x"}
		for k, val := range base {
			m[k] = val
		}
		m["SCHEDULE_INTERVAL"] = v
		return Load(env(m))
	}
	for v, want := range map[string]time.Duration{"": 24 * time.Hour, "6h": 6 * time.Hour, "off": 0, "0": 0} {
		c, err := with(v)
		if err != nil || c.ScheduleInterval != want {
			t.Errorf("%q -> %v err %v, want %v", v, c.ScheduleInterval, err, want)
		}
	}
	for _, v := range []string{"5m", "-1h", "soon"} {
		if _, err := with(v); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestRetentionDays(t *testing.T) {
	load := func(k, v string) (Config, error) { return Load(env(map[string]string{"DATABASE_URL": "x", k: v})) }
	if c, err := load("X", ""); err != nil || c.RetentionScanDays != 180 || c.RetentionAuditDays != 365 {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	if c, _ := load("RETENTION_SCAN_DAYS", "off"); c.RetentionScanDays != 0 {
		t.Error("off should keep forever")
	}
	if c, _ := load("RETENTION_AUDIT_DAYS", "90"); c.RetentionAuditDays != 90 {
		t.Error("90 not applied")
	}
	for _, v := range []string{"7", "-1", "abc", "99999"} {
		if _, err := load("RETENTION_SCAN_DAYS", v); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}
