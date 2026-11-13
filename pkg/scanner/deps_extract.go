package scanner

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Dependency is a pinned package found in a lockfile or manifest.
type Dependency struct {
	Ecosystem string // OSV ecosystem name: npm, Go, PyPI
	Name      string
	Version   string
	Path      string // file it was found in
}

// MaxDependencies bounds how many packages one scan will look up.
const MaxDependencies = 5000

var (
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9@/._~+-]{0,213}$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,99}$`)
	pyReq     = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)\s*(;.*|#.*)?$`)
)

// ExtractDependencies returns pinned dependencies from supported files:
// package-lock.json (npm), go.mod (Go) and requirements.txt (PyPI, == pins only).
// Names and versions come from untrusted files, so anything that does not match a
// conservative pattern is dropped. The result is sorted, de-duplicated and capped.
func ExtractDependencies(path string, content []byte) []Dependency {
	var deps []Dependency
	switch base(path) {
	case "package-lock.json":
		deps = npmLock(path, content)
	case "go.mod":
		deps = goMod(path, content)
	case "requirements.txt":
		deps = pyRequirements(path, content)
	}
	return cleanDeps(deps)
}

func cleanDeps(in []Dependency) []Dependency {
	seen := map[Dependency]bool{}
	out := make([]Dependency, 0, len(in))
	for _, d := range in {
		if !nameRe.MatchString(d.Name) || !versionRe.MatchString(d.Version) || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	if len(out) > MaxDependencies {
		out = out[:MaxDependencies]
	}
	return out
}

func npmLock(path string, content []byte) []Dependency {
	var lock struct {
		Packages map[string]struct {
			Version string
			Link    bool
		} `json:"packages"`
		Dependencies map[string]npmLegacy `json:"dependencies"`
	}
	if json.Unmarshal(content, &lock) != nil {
		return nil
	}
	var out []Dependency
	for key, p := range lock.Packages {
		i := strings.LastIndex(key, "node_modules/")
		if key == "" || i < 0 || p.Link || p.Version == "" {
			continue
		}
		out = append(out, Dependency{"npm", key[i+len("node_modules/"):], p.Version, path})
	}
	if len(lock.Packages) == 0 { // lockfileVersion 1
		var walk func(map[string]npmLegacy, int)
		walk = func(m map[string]npmLegacy, depth int) {
			if depth > 20 {
				return
			}
			for name, d := range m {
				if d.Version != "" {
					out = append(out, Dependency{"npm", name, d.Version, path})
				}
				walk(d.Dependencies, depth+1)
			}
		}
		walk(lock.Dependencies, 0)
	}
	return out
}

type npmLegacy struct {
	Version      string               `json:"version"`
	Dependencies map[string]npmLegacy `json:"dependencies"`
}

func goMod(path string, content []byte) []Dependency {
	var out []Dependency
	inBlock := false
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		switch {
		case line == "require (":
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		case strings.HasPrefix(line, "require ") && !strings.HasSuffix(line, "("):
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		case !inBlock:
			continue
		}
		f := strings.Fields(line)
		if len(f) == 2 && strings.HasPrefix(f[1], "v") {
			out = append(out, Dependency{"Go", f[0], strings.TrimPrefix(f[1], "v"), path}) // OSV Go versions have no "v" prefix
		}
	}
	return out
}

func pyRequirements(path string, content []byte) []Dependency {
	var out []Dependency
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if m := pyReq.FindStringSubmatch(line); m != nil {
			out = append(out, Dependency{"PyPI", strings.ToLower(strings.ReplaceAll(m[1], "_", "-")), m[3], path})
		}
	}
	return out
}

// Advisory is the part of an OSV record PolinChaser uses.
type Advisory struct {
	ID       string
	Summary  string
	Severity string // normalised: critical, high, medium, low; empty if unknown
}

var advisoryIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$`)

// ValidAdvisoryID reports whether id is safe to place in a URL and report.
func ValidAdvisoryID(id string) bool { return advisoryIDRe.MatchString(id) }

// AdvisoryFinding builds a finding for a dependency that matches an advisory.
// "MAL-" advisories are malicious-package reports from the OSV database. They are
// reported as high confidence but never as confirmed_signature, because they are an
// external report and not an exact PolinChaser signature. All other advisories are
// ordinary vulnerabilities and are a different category from malware.
func AdvisoryFinding(d Dependency, a Advisory) (Finding, bool) {
	if !ValidAdvisoryID(a.ID) || !nameRe.MatchString(d.Name) || !versionRe.MatchString(d.Version) {
		return Finding{}, false
	}
	sev := Severity(a.Severity)
	switch sev {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
	default:
		sev = SeverityMedium
	}
	link := "https://osv.dev/vulnerability/" + a.ID
	summary := cleanText(a.Summary, 200)
	pkg := d.Name + "@" + d.Version
	f := Finding{Path: d.Path, Confidence: ConfidenceHigh, Evidence: strings.TrimSpace(a.ID + " " + pkg + ": " + summary)}
	if strings.HasPrefix(strings.ToUpper(a.ID), "MAL-") {
		f.RuleID, f.RuleVersion, f.Category, f.Severity = "PC-DEP-MAL-001", ruleVersion, CatMaliciousDep, SeverityCritical
		f.Title = "Package reported as malicious: " + pkg
		f.Explanation = fmt.Sprintf("The OSV database lists %s as a reported malicious package (%s). This is an external report, not a PolinChaser signature match, so verify it before acting.", pkg, a.ID)
		f.Remediation = "Do not install or deploy. Remove the dependency, check lockfile history and CI logs for when it was added, and rotate credentials that were reachable where it was installed. Details: " + link
	} else {
		f.RuleID, f.RuleVersion, f.Category, f.Severity = "PC-DEP-VULN-001", ruleVersion, CatVulnerableDep, sev
		f.Title = fmt.Sprintf("Known vulnerability %s in %s", a.ID, pkg)
		f.Explanation = fmt.Sprintf("%s is listed in the OSV vulnerability database as affected by %s. This is a known flaw in the package, not evidence of malware.", pkg, a.ID)
		f.Remediation = "Upgrade to a version that fixes this advisory. Details: " + link
	}
	f.seal(d.Ecosystem + "\x00" + d.Name + "\x00" + d.Version + "\x00" + a.ID)
	return f, true
}

func cleanText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsControl(r):
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
		if b.Len() >= max {
			break
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}
