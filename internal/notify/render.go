package notify

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"
	"unicode"
)

type AlertFinding struct {
	Path       string
	Line       int
	Title      string
	Severity   string
	Confidence string
	Category   string
}

// Alert holds everything an email shows. It deliberately has no field for
// evidence or code: payloads and secrets can never reach an email.
type Alert struct {
	Repo      string
	Branch    string
	Commit    string
	PRNumber  int
	Author    string
	Time      time.Time
	Findings  []AlertFinding
	ReportURL string
}

const maxListed = 25

func (a Alert) confirmed() bool {
	for _, f := range a.Findings {
		if f.Confidence == "confirmed_signature" {
			return true
		}
	}
	return false
}

func (a Alert) hasCredentials() bool {
	for _, f := range a.Findings {
		if f.Category == "credential_exposure" {
			return true
		}
	}
	return false
}

func (a Alert) worst() string {
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		for _, f := range a.Findings {
			if f.Severity == s {
				return s
			}
		}
	}
	return "info"
}

// Subject never states a heuristic as confirmed malware.
func (a Alert) Subject() string {
	repo := clean(a.Repo)
	if a.confirmed() {
		return "Known malware indicator detected in " + repo
	}
	return fmt.Sprintf("Security findings in %s (%s severity)", repo, a.worst())
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

func (a Alert) short() string {
	if len(a.Commit) > 7 {
		return a.Commit[:7]
	}
	return a.Commit
}

func (a Alert) listed() (shown []AlertFinding, more int) {
	if len(a.Findings) > maxListed {
		return a.Findings[:maxListed], len(a.Findings) - maxListed
	}
	return a.Findings, 0
}

const deploymentNote = "PolinChaser reports the result to GitHub as a check. Merges and deployments are only blocked if required status checks or deployment gating are configured for this repository."

func actions(a Alert) []string {
	out := []string{
		"Do not merge or deploy this commit until it has been reviewed.",
		"Inspect the affected files and the commit history.",
		"Review editor, CI and package-install configuration for automatic execution.",
	}
	if a.hasCredentials() {
		out = append(out, "Revoke and rotate any exposed credentials. Removing a secret from the latest commit does not invalidate it.")
	} else {
		out = append(out, "If compromise is confirmed or reasonably suspected, rotate credentials reachable from affected machines.")
	}
	return out
}

var htmlTmpl = template.Must(template.New("alert").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;background:#f4f5f7;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1a1d23">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="100%" style="max-width:600px;background:#fff;border:1px solid #dfe2e8;border-radius:6px" cellpadding="0" cellspacing="0">
<tr><td style="padding:20px 24px;border-bottom:1px solid #dfe2e8;font-size:12px;letter-spacing:.08em;color:#5b6270">POLINCHASER SECURITY ALERT</td></tr>
<tr><td style="padding:20px 24px">
<p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#b42318;text-transform:uppercase">{{.Worst}} severity</p>
<h1 style="margin:0 0 16px;font-size:20px;line-height:1.3">{{.Subject}}</h1>
<table role="presentation" cellpadding="0" cellspacing="0" style="font-size:14px;line-height:1.6">
<tr><td style="color:#5b6270;padding-right:16px">Repository</td><td>{{.Repo}}</td></tr>
{{if .Branch}}<tr><td style="color:#5b6270;padding-right:16px">Branch</td><td>{{.Branch}}</td></tr>{{end}}
{{if .PRNumber}}<tr><td style="color:#5b6270;padding-right:16px">Pull request</td><td>#{{.PRNumber}}</td></tr>{{end}}
<tr><td style="color:#5b6270;padding-right:16px">Commit</td><td style="font-family:Menlo,Consolas,monospace">{{.Short}}</td></tr>
{{if .Author}}<tr><td style="color:#5b6270;padding-right:16px">Author (Git metadata)</td><td>{{.Author}}</td></tr>{{end}}
<tr><td style="color:#5b6270;padding-right:16px">Time</td><td>{{.When}}</td></tr>
</table>
<h2 style="margin:24px 0 8px;font-size:15px">Findings ({{.Total}})</h2>
{{range .Shown}}<div style="border-left:3px solid #b42318;padding:4px 0 4px 12px;margin:0 0 10px;font-size:14px">
<div style="font-family:Menlo,Consolas,monospace;word-break:break-all">{{.Path}}{{if .Line}}:{{.Line}}{{end}}</div>
<div>{{.Title}}</div>
<div style="color:#5b6270;font-size:12px">{{.Severity}} severity · {{.Confidence}} confidence</div></div>{{end}}
{{if .More}}<p style="font-size:13px;color:#5b6270">…and {{.More}} more in the full report.</p>{{end}}
{{if .Confirmed}}<p style="font-size:13px;background:#fef3f2;padding:10px;border-radius:4px">At least one finding matched an exact known-malware signature.</p>
{{else}}<p style="font-size:13px;background:#f4f5f7;padding:10px;border-radius:4px">These are heuristic detections. They are not confirmed malware identifications.</p>{{end}}
<h2 style="margin:24px 0 8px;font-size:15px">Deployment status</h2>
<p style="margin:0;font-size:14px">{{.DeploymentNote}}</p>
<h2 style="margin:24px 0 8px;font-size:15px">Recommended actions</h2>
<ol style="margin:0;padding-left:20px;font-size:14px;line-height:1.6">{{range .Actions}}<li>{{.}}</li>{{end}}</ol>
{{if .ReportURL}}<p style="margin:28px 0 0"><a href="{{.ReportURL}}" style="background:#1a1d23;color:#fff;text-decoration:none;padding:12px 20px;border-radius:4px;font-size:14px;display:inline-block">View Security Report</a></p>{{end}}
</td></tr>
<tr><td style="padding:16px 24px;border-top:1px solid #dfe2e8;font-size:12px;color:#5b6270">Suspicious code and credentials are never included in emails. This alert does not identify a person's location.</td></tr>
</table></td></tr></table></body></html>`))

// Render returns subject, HTML and plain text. html/template escapes every
// attacker-controllable field (paths, titles, branch names, author).
func Render(a Alert) (subject, htmlBody, text string, err error) {
	shown, more := a.listed()
	data := map[string]any{
		"Subject": a.Subject(), "Worst": a.worst(), "Repo": clean(a.Repo), "Branch": clean(a.Branch), "PRNumber": a.PRNumber,
		"Short": clean(a.short()), "Author": clean(a.Author), "When": a.Time.UTC().Format("2 January 2006, 15:04 UTC"),
		"Total": len(a.Findings), "Shown": shown, "More": more, "Confirmed": a.confirmed(),
		"DeploymentNote": deploymentNote, "Actions": actions(a), "ReportURL": a.ReportURL,
	}
	var b bytes.Buffer
	if err := htmlTmpl.Execute(&b, data); err != nil {
		return "", "", "", err
	}
	var t strings.Builder
	fmt.Fprintf(&t, "POLINCHASER SECURITY ALERT\n\n%s\n\nRepository: %s\n", a.Subject(), clean(a.Repo))
	if a.Branch != "" {
		fmt.Fprintf(&t, "Branch: %s\n", clean(a.Branch))
	}
	fmt.Fprintf(&t, "Commit: %s\nTime: %s\n\nFindings (%d):\n", clean(a.short()), data["When"], len(a.Findings))
	for _, f := range shown {
		loc := clean(f.Path)
		if f.Line > 0 {
			loc += fmt.Sprintf(":%d", f.Line)
		}
		fmt.Fprintf(&t, "- %s\n  %s [%s severity, %s confidence]\n", loc, clean(f.Title), f.Severity, f.Confidence)
	}
	if more > 0 {
		fmt.Fprintf(&t, "...and %d more in the full report.\n", more)
	}
	fmt.Fprintf(&t, "\nDeployment status: %s\n\nRecommended actions:\n", deploymentNote)
	for i, s := range actions(a) {
		fmt.Fprintf(&t, "%d. %s\n", i+1, s)
	}
	if a.ReportURL != "" {
		fmt.Fprintf(&t, "\nView Security Report: %s\n", a.ReportURL)
	}
	return a.Subject(), b.String(), t.String(), nil
}
