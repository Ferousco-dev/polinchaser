package scanner

import (
	"context"
	"regexp"
	"strings"
)

// PersistenceDetector inspects editor, git-hook and package-manager config
// that can run code automatically without an explicit developer action.
type PersistenceDetector struct{}

func (PersistenceDetector) ID() string { return "persistence" }

var (
	folderOpen = regexp.MustCompile(`"runOn"\s*:\s*"folderOpen"`)
	riskyCmd   = regexp.MustCompile(`(?i)(curl|wget|powershell|\bnode\s+-e|base64|\beval\b|\bbash\s+-c|\bsh\s+-c|\bmshta\b|cmd(\.exe)?\s+/c)`)
	autoTasks  = regexp.MustCompile(`"task\.allowAutomaticTasks"\s*:\s*"on"`)
)

func (PersistenceDetector) Detect(_ context.Context, f File) []Finding {
	var out []Finding
	p, b := f.Path, base(f.Path)
	add := func(id, title, why string, sev Severity, conf Confidence, ln int) {
		fd := Finding{
			RuleID: id, RuleVersion: ruleVersion, Category: CatPersistence, Severity: sev, Confidence: conf,
			Path: p, LineStart: ln, LineEnd: ln, Title: title, Evidence: title,
			Explanation: why,
			Remediation: "Remove the entry unless it is intentional and reviewed. Check other developer machines that opened this repository.",
		}
		fd.seal(id)
		out = append(out, fd)
	}
	switch {
	case strings.HasSuffix(p, ".vscode/tasks.json"):
		if loc := folderOpen.FindIndex(f.Content); loc != nil {
			sev, conf := SeverityMedium, ConfidenceMedium
			if riskyCmd.Match(f.Content) {
				sev, conf = SeverityHigh, ConfidenceHigh
			}
			add("PC-PER-VSC-001", "VS Code task runs automatically when the folder is opened",
				"Tasks with runOn=folderOpen execute as soon as a developer trusts the workspace and are used to persist malware.",
				sev, conf, lineOf(f.Content, loc[0]))
		}
	case strings.HasSuffix(p, ".vscode/settings.json"):
		if loc := autoTasks.FindIndex(f.Content); loc != nil {
			add("PC-PER-VSC-002", "VS Code automatic tasks enabled",
				"Enabling task.allowAutomaticTasks lets folder-open tasks run without prompting.", SeverityMedium, ConfidenceMedium, lineOf(f.Content, loc[0]))
		}
	case b == "temp_auto_push.bat":
		add("PC-PER-BAT-001", "Known suspicious auto-push script name",
			"A temp_auto_push.bat file at the repository root has been reported alongside PolinRider activity.", SeverityHigh, ConfidenceMedium, 0)
	case strings.HasPrefix(p, ".husky/") || strings.HasPrefix(p, ".githooks/") || strings.Contains(p, "/hooks/") && !strings.HasSuffix(p, ".sample"):
		if staticPatterns[3].re.Match(f.Content) || riskyCmd.Match(f.Content) && regexp.MustCompile(`(?i)(curl|wget)`).Match(f.Content) {
			add("PC-PER-HOOK-001", "Git hook downloads or decodes content",
				"Hooks run on every developer's machine automatically and are a persistence vector.", SeverityHigh, ConfidenceMedium, 0)
		}
	case b == ".npmrc":
		for _, l := range strings.Split(string(f.Content), "\n") {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "registry=") && !strings.Contains(l, "registry.npmjs.org") {
				add("PC-PER-NPMRC-001", "Custom package registry configured",
					"A non-default registry can redirect installs to attacker-controlled packages (dependency confusion).", SeverityLow, ConfidenceLow, 0)
				break
			}
		}
	case b == "dockerfile" || strings.HasPrefix(b, "dockerfile."):
		if staticPatterns[3].re.Match(f.Content) {
			add("PC-PER-DOCKER-001", "Dockerfile pipes a remote script to a shell",
				"Executing unverified remote scripts at image build time is a supply-chain risk.", SeverityLow, ConfidenceMedium, 0)
		}
	}
	return out
}
