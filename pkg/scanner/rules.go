package scanner

import (
	"crypto/sha256"
	"encoding/hex"
)

// Signature is an exact indicator. Exact signatures are the only thing that
// may produce ConfidenceConfirmed. Provenance is mandatory.
type Signature struct {
	ID         string
	Family     string
	Substring  string // exact byte substring; empty if SHA256 is used
	SHA256     string // hex digest of whole file
	Severity   Severity
	Provenance string
	Version    string
}

// RuleSet is a versioned, immutable bundle of signatures.
type RuleSet struct {
	Version    string
	Signatures []Signature
}

// BuiltinRules ships only indicators publicly reported by the sources named
// in Provenance. They must be re-verified against primary sources before
// being relied on (see docs/DETECTION-ENGINE.md). No third-party database is
// redistributed. EICAR-style test signature is included for safe testing.
func BuiltinRules() RuleSet {
	const v = "builtin-1"
	return RuleSet{Version: v, Signatures: []Signature{
		{ID: "PC-SIG-TEST-001", Family: "polinchaser-test", Substring: "POLINCHASER-TEST-MALWARE-SIGNATURE-DO-NOT-EXECUTE",
			Severity: SeverityCritical, Version: v, Provenance: "PolinChaser harmless test marker"},
		{ID: "PC-SIG-POLINRIDER-001", Family: "PolinRider", Substring: "rmcej%otb%",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware/PolinRider YARA marker (secondary reporting; verify)"},
		{ID: "PC-SIG-POLINRIDER-C2-001", Family: "PolinRider", Substring: "gowreesh-vt.github.io",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware PolinRider C2 indicator (secondary reporting; verify)"},
		{ID: "PC-SIG-POLINRIDER-C2-002", Family: "PolinRider", Substring: "shop.ceenami.com",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware PolinRider C2 indicator (secondary reporting; verify)"},
	}}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
