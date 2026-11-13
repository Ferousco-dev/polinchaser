package policy

import (
	"testing"

	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

func res(st scanner.Status, fs ...scanner.Finding) scanner.Result {
	return scanner.Result{Status: st, Findings: fs, FilesScanned: 3}
}
func f(s scanner.Severity, c scanner.Confidence) scanner.Finding {
	return scanner.Finding{Severity: s, Confidence: c}
}

func TestConclusions(t *testing.T) {
	cases := []struct {
		name string
		r    scanner.Result
		want string
	}{
		{"clean", res(scanner.StatusClean), "success"},
		{"info only", res(scanner.StatusFindings, f(scanner.SeverityInfo, scanner.ConfidenceLow)), "success"},
		{"low only", res(scanner.StatusFindings, f(scanner.SeverityLow, scanner.ConfidenceHigh)), "success"},
		{"medium warns", res(scanner.StatusFindings, f(scanner.SeverityMedium, scanner.ConfidenceMedium)), "neutral"},
		{"high fails", res(scanner.StatusFindings, f(scanner.SeverityHigh, scanner.ConfidenceLow)), "failure"},
		{"critical confirmed fails", res(scanner.StatusFindings, f(scanner.SeverityCritical, scanner.ConfidenceConfirmed)), "failure"},
		{"incomplete is not success", res(scanner.StatusIncomplete), "neutral"},
		{"failed is not success", res(scanner.StatusFailed), "failure"},
		{"timeout is not success", res(scanner.StatusTimedOut), "timed_out"},
		{"incomplete with blocking still fails", res(scanner.StatusIncomplete, f(scanner.SeverityHigh, scanner.ConfidenceHigh)), "failure"},
	}
	for _, c := range cases {
		if got := Evaluate(Default(), c.r).Conclusion; got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestHeuristicNeverCalledConfirmed(t *testing.T) {
	d := Evaluate(Default(), res(scanner.StatusFindings, f(scanner.SeverityCritical, scanner.ConfidenceMedium)))
	if d.Conclusion != "failure" {
		t.Fatal("critical heuristic must still block")
	}
	for _, bad := range []string{"Known malware", "exact known-malware"} {
		if contains(d.Title+d.Summary, bad) {
			t.Fatalf("heuristic described as confirmed: %q", d.Title+d.Summary)
		}
	}
	if !contains(d.Summary, "not a confirmed malware") && !contains(d.Summary, "none is a confirmed") {
		t.Fatalf("summary should disclaim: %s", d.Summary)
	}
}

func TestConfiguredThreshold(t *testing.T) {
	p := Policy{FailOn: scanner.SeverityCritical, WarnOn: scanner.SeverityHigh}
	if got := Evaluate(p, res(scanner.StatusFindings, f(scanner.SeverityHigh, scanner.ConfidenceHigh))).Conclusion; got != "neutral" {
		t.Fatal(got)
	}
}

func contains(s, sub string) bool { return len(sub) > 0 && indexOf(s, sub) >= 0 }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestDependencyVulnerabilityCappedAtWarningButMalwareStillBlocks(t *testing.T) {
	vuln := scanner.Finding{Category: scanner.CatVulnerableDep, Severity: scanner.SeverityCritical, Confidence: scanner.ConfidenceHigh}
	d := Evaluate(Default(), scanner.Result{Status: scanner.StatusFindings, Findings: []scanner.Finding{vuln}})
	if d.Conclusion == "failure" || d.Blocking != 0 {
		t.Errorf("critical dependency CVE blocked the check: %+v", d)
	}
	mal := scanner.Finding{Category: scanner.CatMaliciousDep, Severity: scanner.SeverityCritical, Confidence: scanner.ConfidenceHigh}
	d = Evaluate(Default(), scanner.Result{Status: scanner.StatusFindings, Findings: []scanner.Finding{mal}})
	if d.Conclusion != "failure" {
		t.Errorf("malicious package report did not block: %+v", d)
	}
}
