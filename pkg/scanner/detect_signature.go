package scanner

import (
	"bytes"
	"context"
)

const ruleVersion = "1"

// SignatureDetector reports exact-match indicators only.
type SignatureDetector struct{ rules RuleSet }

func NewSignatureDetector(r RuleSet) SignatureDetector { return SignatureDetector{r} }
func (SignatureDetector) ID() string                   { return "signature" }

func (d SignatureDetector) Detect(_ context.Context, f File) []Finding {
	var out []Finding
	var digest string
	for _, s := range d.rules.Signatures {
		var line int
		hit := false
		switch {
		case s.Substring != "":
			if i := bytes.Index(f.Content, []byte(s.Substring)); i >= 0 {
				hit, line = true, lineOf(f.Content, i)
			}
		case s.SHA256 != "" && !f.Truncated:
			if digest == "" {
				digest = sha256Hex(f.Content)
			}
			hit = digest == s.SHA256
		}
		if !hit {
			continue
		}
		fd := Finding{
			RuleID: s.ID, RuleVersion: s.Version, Category: CatKnownMalware,
			Severity: s.Severity, Confidence: ConfidenceConfirmed, Path: f.Path,
			LineStart: line, LineEnd: line,
			Title:       "Known " + s.Family + " indicator matched",
			Evidence:    "Exact signature " + s.ID + " (" + s.Provenance + ")",
			Explanation: "The file contains an exact indicator associated with the " + s.Family + " family. Payload content is intentionally not reproduced.",
			Remediation: "Do not merge or deploy. Inspect the file and its history, remove the code, review editor/CI configuration for persistence, and rotate credentials that were reachable from affected machines.",
		}
		fd.seal(s.ID)
		out = append(out, fd)
	}
	return out
}
