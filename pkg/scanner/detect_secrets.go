package scanner

import (
	"context"
	"regexp"
)

// SecretsDetector finds committed credentials. Secrets are never stored or
// shown in full: evidence is masked and the fingerprint uses a digest.
type SecretsDetector struct{}

func (SecretsDetector) ID() string { return "secrets" }

type secretRule struct {
	id, name string
	re       *regexp.Regexp
	conf     Confidence
}

var secretRules = []secretRule{
	{"PC-SEC-AWS-001", "AWS access key ID", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), ConfidenceHigh},
	{"PC-SEC-GH-001", "GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`), ConfidenceHigh},
	{"PC-SEC-GH-002", "GitHub fine-grained token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{50,}\b`), ConfidenceHigh},
	{"PC-SEC-KEY-001", "Private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`), ConfidenceHigh},
	{"PC-SEC-SLACK-001", "Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), ConfidenceHigh},
	{"PC-SEC-STRIPE-001", "Stripe live secret key", regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`), ConfidenceHigh},
	{"PC-SEC-RESEND-001", "Resend API key", regexp.MustCompile(`\bre_[A-Za-z0-9_]{24,}\b`), ConfidenceMedium},
	{"PC-SEC-RENDER-001", "Render API key", regexp.MustCompile(`\brnd_[A-Za-z0-9]{24,}\b`), ConfidenceMedium},
	{"PC-SEC-DB-001", "Database URL with password", regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:/@'"]+:[^\s@'"]{3,}@[^\s'"]+`), ConfidenceMedium},
}

func (SecretsDetector) Detect(_ context.Context, f File) []Finding {
	var out []Finding
	for _, r := range secretRules {
		for _, loc := range r.re.FindAllIndex(f.Content, 5) {
			val := string(f.Content[loc[0]:loc[1]])
			ln := lineOf(f.Content, loc[0])
			shown := mask(val)
			if r.id == "PC-SEC-KEY-001" {
				shown = "private key header"
			}
			fd := Finding{
				RuleID: r.id, RuleVersion: ruleVersion, Category: CatCredentialExpose, Severity: SeverityHigh, Confidence: r.conf,
				Path: f.Path, LineStart: ln, LineEnd: ln, Title: r.name + " committed to repository",
				Evidence:    shown,
				Explanation: "A credential appears in repository content. Removing it from the latest commit does not revoke it: it remains in git history and may already be exposed.",
				Remediation: "Revoke and rotate the credential immediately, then remove it from history if required. Treat it as compromised.",
			}
			fd.seal(sha256Hex([]byte(val)))
			out = append(out, fd)
		}
	}
	return out
}
