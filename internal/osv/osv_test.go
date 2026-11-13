package osv_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ferousco-dev/polinchaser/internal/osv"
	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

func deps() []scanner.Dependency {
	return []scanner.Dependency{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.0", Path: "package-lock.json"},
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Path: "package-lock.json"},
		{Ecosystem: "npm", Name: "evil-pkg", Version: "0.0.1", Path: "package-lock.json"},
	}
}

func server(t *testing.T, batchStatus int) (*httptest.Server, *[]string) {
	var bodies []string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if batchStatus != 200 {
			w.WriteHeader(batchStatus)
			return
		}
		io.WriteString(w, `{"results":[{"vulns":[{"id":"GHSA-aaaa-bbbb-cccc"}]},{},{"vulns":[{"id":"MAL-2026-1234"}]}]}`)
	})
	mux.HandleFunc("GET /v1/vulns/GHSA-aaaa-bbbb-cccc", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"id":"GHSA-aaaa-bbbb-cccc","summary":"Prototype pollution\nin lodash","database_specific":{"severity":"HIGH"}}`)
	})
	mux.HandleFunc("GET /v1/vulns/MAL-2026-1234", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"id":"MAL-2026-1234","summary":"Malicious code in evil-pkg"}`)
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s, &bodies
}

func TestCheckMapsVulnerabilitiesAndMaliciousPackages(t *testing.T) {
	s, bodies := server(t, 200)
	fs, err := osv.New(s.URL+"/").Check(context.Background(), deps())
	if err != nil || len(fs) != 2 {
		t.Fatalf("findings=%d err=%v", len(fs), err)
	}
	var vuln, mal *scanner.Finding
	for i := range fs {
		switch fs[i].Category {
		case scanner.CatVulnerableDep:
			vuln = &fs[i]
		case scanner.CatMaliciousDep:
			mal = &fs[i]
		}
	}
	if vuln == nil || vuln.Severity != scanner.SeverityHigh || vuln.Confidence == scanner.ConfidenceConfirmed || !strings.Contains(vuln.Title, "lodash@4.17.0") {
		t.Errorf("vulnerability finding wrong: %+v", vuln)
	}
	if strings.ContainsAny(vuln.Evidence, "\n\r") {
		t.Errorf("control characters from advisory text survived: %q", vuln.Evidence)
	}
	if !strings.Contains(vuln.Explanation, "not evidence of malware") {
		t.Error("vulnerability explanation must say it is not malware")
	}
	if mal == nil || mal.Severity != scanner.SeverityCritical || mal.Confidence != scanner.ConfidenceHigh {
		t.Errorf("malicious-package finding wrong: %+v", mal)
	}
	if mal != nil && mal.Confidence == scanner.ConfidenceConfirmed {
		t.Error("an OSV malicious-package report must never be confirmed_signature")
	}
	// Privacy: only package, ecosystem and version leave the server.
	req := (*bodies)[0]
	if strings.Contains(req, "package-lock.json") || strings.Contains(req, "Path") {
		t.Errorf("file path leaked into OSV request: %s", req)
	}
	var parsed struct {
		Queries []map[string]any `json:"queries"`
	}
	_ = json.Unmarshal([]byte(req), &parsed)
	if len(parsed.Queries) != 3 {
		t.Errorf("queries = %d", len(parsed.Queries))
	}
}

func TestCheckReportsFailureSoCallerCanMarkScanIncomplete(t *testing.T) {
	s, _ := server(t, 503)
	fs, err := osv.New(s.URL).Check(context.Background(), deps())
	if err == nil {
		t.Fatal("HTTP 503 must return an error, not an empty clean result")
	}
	if len(fs) != 0 {
		t.Errorf("findings = %d", len(fs))
	}
	if strings.Contains(err.Error(), s.URL) {
		t.Error("error should not embed the request URL")
	}
}

func TestMissingDetailsStillReportsTheFinding(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"results":[{"vulns":[{"id":"GHSA-zzzz-yyyy-xxxx"}]},{},{}]}`)
	})
	s := httptest.NewServer(mux) // detail endpoint returns 404
	defer s.Close()
	fs, err := osv.New(s.URL).Check(context.Background(), deps())
	if err != nil || len(fs) != 1 || fs[0].Severity != scanner.SeverityMedium {
		t.Fatalf("findings=%v err=%v", fs, err)
	}
}
