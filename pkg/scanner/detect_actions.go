package scanner

import (
	"context"
	"regexp"
	"strings"
)

// ActionsDetector reviews GitHub Actions workflows. Findings here are
// security recommendations or risky patterns, never confirmed malware.
type ActionsDetector struct{}

func (ActionsDetector) ID() string { return "actions" }

var (
	usesRe      = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*([^\s#]+)`)
	shaRe       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	injectRe    = regexp.MustCompile(`\$\{\{\s*github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label)|comment\.body|review\.body|head_commit\.message|commits\[[^\]]*\]\.message)\s*\}\}`)
	prTargetRe  = regexp.MustCompile(`\bpull_request_target\b`)
	headCheckRe = regexp.MustCompile(`github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref`)
	writeAllRe  = regexp.MustCompile(`(?m)^\s*permissions:\s*write-all`)
)

func (ActionsDetector) Detect(_ context.Context, f File) []Finding {
	if !strings.HasPrefix(f.Path, ".github/workflows/") || (ext(f.Path) != ".yml" && ext(f.Path) != ".yaml") {
		return nil
	}
	var out []Finding
	add := func(id, title, why string, sev Severity, conf Confidence, cat Category, ln int) {
		fd := Finding{
			RuleID: id, RuleVersion: ruleVersion, Category: cat, Severity: sev, Confidence: conf,
			Path: f.Path, LineStart: ln, LineEnd: ln, Title: title, Evidence: title, Explanation: why,
			Remediation: "Follow GitHub's security hardening guidance: pin actions to commit SHAs, use least-privilege permissions and pass untrusted input via environment variables.",
		}
		fd.seal(id + itoa(ln))
		out = append(out, fd)
	}
	for _, m := range usesRe.FindAllSubmatchIndex(f.Content, -1) {
		ref := string(f.Content[m[2]:m[3]])
		if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
			continue
		}
		at := strings.LastIndex(ref, "@")
		if at < 0 || shaRe.MatchString(ref[at+1:]) {
			continue
		}
		if strings.HasPrefix(ref, "actions/") || strings.HasPrefix(ref, "github/") {
			continue
		}
		add("PC-CI-PIN-001", "Third-party action not pinned to a commit SHA: "+ref[:at],
			"Mutable tags can be moved to malicious code after review (as in past action supply-chain compromises).", SeverityLow, ConfidenceHigh, CatCICD, lineOf(f.Content, m[0]))
	}
	for _, m := range injectRe.FindAllIndex(f.Content, 5) {
		add("PC-CI-INJ-001", "Untrusted event data interpolated into a workflow",
			"Interpolating attacker-controlled fields (titles, bodies, branch names) into run steps allows script injection.", SeverityHigh, ConfidenceMedium, CatCICD, lineOf(f.Content, m[0]))
	}
	if loc := prTargetRe.FindIndex(f.Content); loc != nil && headCheckRe.Match(f.Content) {
		add("PC-CI-PRT-001", "pull_request_target checks out untrusted PR code",
			"pull_request_target runs with secrets and write access; checking out the PR head executes untrusted code in that context.", SeverityHigh, ConfidenceMedium, CatCICD, lineOf(f.Content, loc[0]))
	}
	if loc := writeAllRe.FindIndex(f.Content); loc != nil {
		add("PC-CI-PERM-001", "Workflow grants write-all permissions",
			"Excessive GITHUB_TOKEN permissions increase the impact of any compromised step.", SeverityMedium, ConfidenceHigh, CatCICD, lineOf(f.Content, loc[0]))
	}
	if loc := staticPatterns[3].re.FindIndex(f.Content); loc != nil {
		add("PC-CI-PIPE-001", "Workflow pipes a remote script to a shell",
			"Executing unverified remote scripts in CI exposes secrets to whoever controls that URL.", SeverityMedium, ConfidenceMedium, CatCICD, lineOf(f.Content, loc[0]))
	}
	return out
}
