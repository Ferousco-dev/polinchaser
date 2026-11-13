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
// Indicator strings are written as split constants so this repository does not contain the
// literals and cannot flag itself when scanned.
func BuiltinRules() RuleSet {
	const v = "builtin-2"
	return RuleSet{Version: v, Signatures: []Signature{
		{ID: "PC-SIG-TEST-001", Family: "polinchaser-test", Substring: "POLINCHASER-TEST-MALWARE-SIGNATURE-DO-NOT-EXECUTE",
			Severity: SeverityCritical, Version: v, Provenance: "PolinChaser harmless test marker"},
		{ID: "PC-SIG-POLINRIDER-001", Family: "PolinRider", Substring: "rmcej" + "%otb%",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware/PolinRider README (primary dossier, read 2026-11): original-variant marker"},
		{ID: "PC-SIG-POLINRIDER-002", Family: "PolinRider", Substring: "Cot%3" + "t=shtP",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware/PolinRider README (primary dossier, read 2026-11): newer-variant marker"},
		{ID: "PC-SIG-POLINRIDER-C2-001", Family: "PolinRider", Substring: "260120.v" + "ercel.app",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware/PolinRider README (primary dossier, read 2026-11): reported Vercel C2 host"},
		{ID: "PC-SIG-POLINRIDER-C2-002", Family: "PolinRider", Substring: "default-configur" + "ation.vercel.app",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware/PolinRider README (primary dossier, read 2026-11): reported Vercel C2 host"},
		{ID: "PC-SIG-POLINRIDER-C2-003", Family: "PolinRider", Substring: "vscode-settings-bo" + "otstrap.vercel.app",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware/PolinRider README (primary dossier, read 2026-11): reported Vercel C2 host"},
		{ID: "PC-SIG-POLINRIDER-C2-004", Family: "PolinRider", Substring: "vscode-settings-" + "config.vercel.app",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware/PolinRider README (primary dossier, read 2026-11): reported Vercel C2 host"},
		{ID: "PC-SIG-POLINRIDER-C2-005", Family: "PolinRider", Substring: "vscode-bootstra" + "pper.vercel.app",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware/PolinRider README (primary dossier, read 2026-11): reported Vercel C2 host"},
		{ID: "PC-SIG-POLINRIDER-C2-006", Family: "PolinRider", Substring: "vscode-load-co" + "nfig.vercel.app",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware/PolinRider README (primary dossier, read 2026-11): reported Vercel C2 host"},
		{ID: "PC-SIG-POLINRIDER-C2-007", Family: "PolinRider", Substring: "TMfKQEd7TJJa5xNZJ" + "Z2Lep838vrzrs7mAP",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware/PolinRider README (primary dossier, read 2026-11): reported primary TRON C2 account"},
		{ID: "PC-SIG-POLINRIDER-C2-008", Family: "PolinRider", Substring: "TXfxHUet9pJVU1BgV" + "kBAbrES4YUc1nGzcG",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware/PolinRider README (primary dossier, read 2026-11): reported secondary TRON C2 account"},
		{ID: "PC-SIG-POLINRIDER-C2-009", Family: "PolinRider", Substring: "0xbe037400670fbf1c32364f762975908" + "dc43eeb38759263e7dfcdabc76380811e",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware/PolinRider README (primary dossier, read 2026-11): reported Aptos fallback C2 hash"},
		{ID: "PC-SIG-POLINRIDER-C2-010", Family: "PolinRider", Substring: "0x3f0e5781d0855fb460661ac63257376" + "db1941b2bb522499e4757ecb3ebd5dce3",
			Severity: SeverityCritical, Version: v, Provenance: "OpenSourceMalware/PolinRider README (primary dossier, read 2026-11): reported Aptos fallback C2 hash"},
	}}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
