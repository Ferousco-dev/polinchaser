package scanner

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// DependencyDetector inspects manifests statically. It does NOT resolve
// vulnerabilities: OSV/GHSA lookups are performed by the worker (network
// access is deliberately kept out of this package). Vulnerable-dependency
// findings are a separate category from malware.
type DependencyDetector struct{}

func (DependencyDetector) ID() string { return "dependencies" }

var lifecycleKeys = []string{"preinstall", "install", "postinstall", "prepare", "prepublish", "preuninstall"}
var riskyScript = regexp.MustCompile(`(?i)(curl|wget|powershell|node\s+-e|base64|\beval\b|\|\s*(ba)?sh\b|https?://)`)

var popular = []string{"react", "lodash", "express", "axios", "chalk", "moment", "request", "commander", "debug", "webpack", "typescript", "eslint", "tailwindcss", "postcss", "next", "vue", "jquery", "dotenv", "uuid", "colors"}

func (DependencyDetector) Detect(_ context.Context, f File) []Finding {
	var out []Finding
	switch base(f.Path) {
	case "package.json":
		out = append(out, npmFindings(f)...)
	case "requirements.txt":
		for i, l := range strings.Split(string(f.Content), "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "--extra-index-url") {
				fd := depFinding(f, "PC-DEP-PIP-001", "Extra package index configured", "An extra index lets a same-named public package override a private one (dependency confusion).", SeverityMedium, ConfidenceLow, i+1)
				out = append(out, fd)
			}
		}
	}
	return out
}

func depFinding(f File, id, title, why string, sev Severity, conf Confidence, ln int) Finding {
	fd := Finding{
		RuleID: id, RuleVersion: ruleVersion, Category: CatSupplyChain, Severity: sev, Confidence: conf,
		Path: f.Path, LineStart: ln, LineEnd: ln, Title: title, Evidence: title, Explanation: why,
		Remediation: "Verify the dependency or script is intended, pin exact versions and review the package source.",
	}
	fd.seal(id + title)
	return fd
}

func npmFindings(f File) []Finding {
	var pkg struct {
		Scripts      map[string]string `json:"scripts"`
		Dependencies map[string]string `json:"dependencies"`
		DevDeps      map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(f.Content, &pkg); err != nil {
		return nil
	}
	var out []Finding
	for _, k := range lifecycleKeys {
		s, ok := pkg.Scripts[k]
		if !ok {
			continue
		}
		if riskyScript.MatchString(s) {
			fd := depFinding(f, "PC-DEP-NPM-001", "Install lifecycle script downloads or decodes content",
				"The "+k+" script runs automatically on install and contains network or decoding behaviour. Lifecycle scripts are the main npm malware execution vector.", SeverityHigh, ConfidenceMedium, 0)
			fd.Category = CatMaliciousDep
			fd.Evidence = "script " + k + " matches risky command pattern"
			fd.seal(k)
			out = append(out, fd)
		} else if k != "prepare" {
			out = append(out, depFinding(f, "PC-DEP-NPM-002", "Install lifecycle script present",
				"The "+k+" script runs automatically on install. It does not look malicious but should be reviewed when added or changed.", SeverityInfo, ConfidenceLow, 0))
		}
	}
	all := map[string]string{}
	for k, v := range pkg.Dependencies {
		all[k] = v
	}
	for k, v := range pkg.DevDeps {
		all[k] = v
	}
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		v := all[n]
		if strings.HasPrefix(v, "git+") || strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "github:") {
			out = append(out, depFinding(f, "PC-DEP-NPM-003", "Dependency installed from a URL or git ref: "+n,
				"Dependencies outside the registry bypass registry integrity and malware scanning.", SeverityMedium, ConfidenceLow, 0))
		}
		for _, p := range popular {
			if n != p && editDistance(n, p) == 1 && len(n) >= 4 {
				fd := depFinding(f, "PC-DEP-TYPO-001", "Possible typosquat of '"+p+"': "+n,
					"The package name is one edit away from a popular package, a common typosquatting pattern.", SeverityMedium, ConfidenceLow, 0)
				fd.Category = CatMaliciousDep
				out = append(out, fd)
			}
		}
	}
	return out
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			c := 1
			if a[i-1] == b[j-1] {
				c = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+c)
		}
		prev = cur
	}
	return prev[len(b)]
}
