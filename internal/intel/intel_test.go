package intel_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Ferousco-dev/polinchaser/internal/intel"
	"github.com/Ferousco-dev/polinchaser/internal/testutil"
	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

func feedJSON(sigs ...map[string]any) string {
	b, _ := json.Marshal(map[string]any{"format": 1, "name": "Test feed", "license": "CC0-1.0 (test data)", "signatures": sigs})
	return string(b)
}

func sig(id, substring string) map[string]any {
	return map[string]any{"id": id, "family": "TestFamily", "substring": substring, "severity": "critical", "provenance": "unit test"}
}

func TestParseFeedValidation(t *testing.T) {
	ok := feedJSON(sig("T-1", "evil-marker-123"))
	if _, err := intel.ParseFeed([]byte(ok)); err != nil {
		t.Fatalf("valid feed rejected: %v", err)
	}
	bad := map[string]string{
		"no license":      strings.Replace(ok, `"license":"CC0-1.0 (test data)"`, `"license":""`, 1),
		"unknown field":   strings.Replace(ok, `"format":1`, `"format":1,"extra":true`, 1),
		"reserved prefix": feedJSON(sig("PC-SIG-EVIL", "evil-marker-123")),
		"short substring": feedJSON(sig("T-1", "abc")),
		"both kinds":      feedJSON(map[string]any{"id": "T-1", "family": "F", "substring": "evil-marker-123", "sha256": strings.Repeat("a", 64), "severity": "high", "provenance": "p"}),
		"bad sha":         feedJSON(map[string]any{"id": "T-1", "family": "F", "sha256": "XYZ", "severity": "high", "provenance": "p"}),
		"bad severity":    strings.Replace(ok, `"critical"`, `"apocalyptic"`, 1),
		"dup id":          feedJSON(sig("T-1", "evil-marker-123"), sig("T-1", "evil-marker-456")),
		"no provenance":   strings.Replace(ok, `"provenance":"unit test"`, `"provenance":""`, 1),
		"empty":           feedJSON(),
		"trailing":        ok + `{"x":1}`,
		"bad format":      strings.Replace(ok, `"format":1`, `"format":2`, 1),
		"oversized":       strings.Repeat(" ", intel.MaxFeedBytes+1),
	}
	for name, doc := range bad {
		if _, err := intel.ParseFeed([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type env struct {
	t    *testing.T
	ref  *intel.Refresher
	mgr  *intel.Manager
	body atomic.Value // string
	code atomic.Int32
	hits atomic.Int32
	srv  *httptest.Server
}

func newEnv(t *testing.T, feed string) *env {
	e := &env{t: t}
	e.body.Store(feed)
	e.code.Store(200)
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(304)
			return
		}
		if c := int(e.code.Load()); c != 200 {
			w.WriteHeader(c)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		io.WriteString(w, e.body.Load().(string))
	}))
	t.Cleanup(e.srv.Close)
	pool := testutil.Pool(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e.ref = &intel.Refresher{Pool: pool, URLs: []string{e.srv.URL + "/feed.json?token=SECRET123"}, Client: intel.NewHTTPClient(true), Log: log}
	e.mgr = &intel.Manager{Pool: pool, Builtin: scanner.BuiltinRules(), Log: log}
	return e
}

func TestRefreshAddsSignaturesAndEngineMatchesThem(t *testing.T) {
	e := newEnv(t, feedJSON(sig("T-1", "feed-marker-ABCDEF")))
	ctx := context.Background()
	_, v0 := e.mgr.Current(ctx)
	if v0 != "builtin-1" {
		t.Fatalf("version before refresh = %q", v0)
	}
	e.ref.RefreshAll(ctx)
	eng, v1 := e.mgr.Current(ctx)
	if !strings.HasPrefix(v1, "builtin-1+intel.") {
		t.Fatalf("version after refresh = %q", v1)
	}
	res := eng.Scan(ctx, scanner.MemorySource{"app.js": []byte("const x = 'feed-marker-ABCDEF';")})
	var found bool
	for _, f := range res.Findings {
		if strings.HasPrefix(f.RuleID, "EXT-F") && f.Confidence == scanner.ConfidenceConfirmed {
			found = true
		}
	}
	if !found {
		t.Fatalf("feed signature did not produce a confirmed finding: %+v", res.Findings)
	}
	// Built-in rules still work alongside.
	res = eng.Scan(ctx, scanner.MemorySource{"a.js": []byte("POLINCHASER-TEST-MALWARE-SIGNATURE-DO-NOT-EXECUTE")})
	if len(res.Findings) == 0 {
		t.Error("built-in signature lost after refresh")
	}
}

func TestFailedRefreshKeepsPreviousSignaturesAndHidesURLSecret(t *testing.T) {
	e := newEnv(t, feedJSON(sig("T-1", "feed-marker-ABCDEF")))
	ctx := context.Background()
	e.ref.RefreshAll(ctx)
	_, v1 := e.mgr.Current(ctx)

	e.ref.Client = intel.NewHTTPClient(true)
	e.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "not json at all") })
	e.ref.RefreshAll(ctx)
	_, v2 := e.mgr.Current(ctx)
	if v1 != v2 {
		t.Errorf("version changed after a failed refresh: %s -> %s", v1, v2)
	}
	e.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	e.ref.RefreshAll(ctx)
	if _, v3 := e.mgr.Current(ctx); v3 != v1 {
		t.Errorf("version changed after HTTP 500: %s", v3)
	}
	var status, msg string
	if err := e.ref.Pool.QueryRow(ctx, `SELECT last_status, last_error FROM intel_feeds`).Scan(&status, &msg); err != nil {
		t.Fatal(err)
	}
	if status != "error" || msg == "" {
		t.Errorf("status=%q error=%q", status, msg)
	}
	if strings.Contains(msg, "SECRET123") {
		t.Error("feed URL secret leaked into stored error")
	}
}

func TestETagNotModifiedAndFeedRemoval(t *testing.T) {
	e := newEnv(t, feedJSON(sig("T-1", "feed-marker-ABCDEF")))
	ctx := context.Background()
	e.ref.RefreshAll(ctx)
	e.ref.RefreshAll(ctx)
	var status string
	_ = e.ref.Pool.QueryRow(ctx, `SELECT last_status FROM intel_feeds`).Scan(&status)
	if status != "not_modified" {
		t.Errorf("second refresh status = %q, want not_modified", status)
	}
	// Operator removes the feed from config: its signatures stop applying.
	e.ref.URLs = nil
	e.ref.RefreshAll(ctx)
	if _, v := e.mgr.Current(ctx); v != "builtin-1" {
		t.Errorf("version after removing feed = %q, want builtin-1", v)
	}
}

func TestDefaultClientRefusesLoopbackAndPrivateTargets(t *testing.T) {
	e := newEnv(t, feedJSON(sig("T-1", "feed-marker-ABCDEF")))
	e.ref.Client = intel.NewHTTPClient(false)
	e.ref.RefreshAll(context.Background())
	if e.hits.Load() != 0 {
		t.Fatal("request reached a loopback server through the SSRF-guarded client")
	}
	var n int
	_ = e.ref.Pool.QueryRow(context.Background(), `SELECT count(*) FROM intel_signatures`).Scan(&n)
	if n != 0 {
		t.Error("signatures stored from a blocked fetch")
	}
}
