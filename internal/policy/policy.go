// Package policy turns a scan result into a GitHub check conclusion.
package policy

import (
	"fmt"
	"strings"

	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

// Policy thresholds. Findings at or above FailOn fail the check; findings at
// or above WarnOn (but below FailOn) yield a neutral "warnings" conclusion.
type Policy struct {
	FailOn scanner.Severity
	WarnOn scanner.Severity
}

func Default() Policy { return Policy{FailOn: scanner.SeverityHigh, WarnOn: scanner.SeverityMedium} }

type Decision struct {
	Conclusion string // GitHub check conclusion
	Title      string
	Summary    string
	Blocking   int // findings at/above FailOn
}

// Evaluate never reports a failed, timed-out or incomplete scan as success.
func Evaluate(p Policy, res scanner.Result) Decision {
	blocking, warn, confirmed := 0, 0, 0
	counts := map[scanner.Severity]int{}
	for _, f := range res.Findings {
		counts[f.Severity]++
		rank := f.Severity.Rank()
		// A known vulnerability in a dependency is a warning at most; it never fails the
		// check by itself. Malware signatures and malicious-package reports still block.
		if f.Category == scanner.CatVulnerableDep && rank > scanner.SeverityMedium.Rank() {
			rank = scanner.SeverityMedium.Rank()
		}
		if rank >= p.FailOn.Rank() {
			blocking++
		} else if rank >= p.WarnOn.Rank() {
			warn++
		}
		if f.Confidence == scanner.ConfidenceConfirmed {
			confirmed++
		}
	}
	d := Decision{Blocking: blocking}
	detail := describe(counts, confirmed, res)
	switch {
	case res.Status == scanner.StatusFailed:
		d.Conclusion, d.Title = "failure", "Scan failed: this commit was NOT verified"
	case res.Status == scanner.StatusTimedOut:
		d.Conclusion, d.Title = "timed_out", "Scan timed out: this commit was NOT verified"
	case blocking > 0 && confirmed > 0:
		d.Conclusion, d.Title = "failure", fmt.Sprintf("Known malware indicator detected (%d blocking finding(s))", blocking)
	case blocking > 0:
		d.Conclusion, d.Title = "failure", fmt.Sprintf("%d blocking finding(s): review required", blocking)
	case res.Status == scanner.StatusIncomplete:
		d.Conclusion, d.Title = "neutral", "Scan incomplete: some files were not analysed"
	case warn > 0:
		d.Conclusion, d.Title = "neutral", fmt.Sprintf("%d warning(s)", warn)
	case len(res.Findings) > 0:
		d.Conclusion, d.Title = "success", "No blocking findings (informational items recorded)"
	default:
		d.Conclusion, d.Title = "success", "No findings"
	}
	d.Summary = detail
	return d
}

func describe(c map[scanner.Severity]int, confirmed int, res scanner.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Scanned %d file(s). ", res.FilesScanned)
	var parts []string
	for _, s := range []scanner.Severity{scanner.SeverityCritical, scanner.SeverityHigh, scanner.SeverityMedium, scanner.SeverityLow, scanner.SeverityInfo} {
		if c[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c[s], s))
		}
	}
	if len(parts) > 0 {
		b.WriteString("Findings: " + strings.Join(parts, ", ") + ". ")
		if confirmed > 0 {
			fmt.Fprintf(&b, "%d matched an exact known-malware signature; all others are heuristic detections and are not confirmed malware. ", confirmed)
		} else {
			b.WriteString("All findings are heuristic or policy detections; none is a confirmed malware identification. ")
		}
	}
	if n := len(res.Skipped); n > 0 {
		fmt.Fprintf(&b, "%d file(s) were skipped (size, links or path limits), so this result may be incomplete. ", n)
	}
	if res.Error != "" {
		b.WriteString("Error: scan could not complete. ")
	}
	return strings.TrimSpace(b.String())
}
