package scanner

import (
	"context"
	"regexp"
	"strings"
)

// StaticDetector applies behavioural pattern rules to source files. These are
// heuristics: they never produce ConfidenceConfirmed.
type StaticDetector struct{}

func (StaticDetector) ID() string { return "static" }

type pattern struct {
	id, title, why string
	re             *regexp.Regexp
	sev            Severity
	conf           Confidence
	cat            Category
}

var staticPatterns = []pattern{
	{"PC-STA-EVAL-001", "Dynamic execution of decoded data", "Decoding data and passing it straight to eval/Function is the canonical loader pattern for obfuscated payloads.",
		regexp.MustCompile(`(?i)(eval|new\s+Function)\s*\(\s*(atob|Buffer\.from|unescape|decodeURIComponent|String\.fromCharCode)`), SeverityHigh, ConfidenceHigh, CatSuspiciousCode},
	{"PC-STA-PYEXEC-001", "Python executes decoded data", "exec/eval over base64 or decompressed data hides what runs.",
		regexp.MustCompile(`(?i)\b(exec|eval)\s*\(\s*(base64\.b64decode|zlib\.decompress|codecs\.decode|marshal\.loads)`), SeverityHigh, ConfidenceHigh, CatSuspiciousCode},
	{"PC-STA-PHP-001", "PHP evaluates decoded data or runs shell", "eval/assert over base64_decode or shell_exec with obfuscation is common in PHP backdoors and loaders.",
		regexp.MustCompile(`(?i)\b(eval|assert)\s*\(\s*(base64_decode|gzinflate|str_rot13)`), SeverityHigh, ConfidenceHigh, CatSuspiciousCode},
	{"PC-STA-PIPE-001", "Remote script piped to a shell", "Downloading and executing remote content in one step bypasses review.",
		regexp.MustCompile(`(?i)(curl|wget)\s[^\n|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`), SeverityMedium, ConfidenceMedium, CatSuspiciousCode},
	{"PC-STA-PS-001", "PowerShell download-and-execute or encoded command", "Encoded commands and IEX download cradles are typical of malware droppers.",
		regexp.MustCompile(`(?i)(-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}|\bIEX\b[^\n]{0,60}(DownloadString|Invoke-WebRequest)|DownloadString\([^)]*\)\s*\|\s*IEX)`), SeverityHigh, ConfidenceMedium, CatSuspiciousCode},
	{"PC-STA-CP-001", "Child process spawns a shell with network or decoding", "Spawning a shell that downloads or decodes content is a common stage-one loader.",
		regexp.MustCompile(`(?i)(child_process|execSync|spawnSync|exec)\s*\([^)\n]{0,120}(curl|wget|base64\s+-d|powershell|\|\s*sh)`), SeverityHigh, ConfidenceMedium, CatSuspiciousCode},
	{"PC-STA-WS-001", "WebSocket to a hard-coded raw IP", "Command-and-control channels frequently use WebSockets to bare IP addresses.",
		regexp.MustCompile(`(?i)new\s+WebSocket\s*\(\s*['"\x60]wss?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`), SeverityMedium, ConfidenceLow, CatSuspiciousCode},
	{"PC-STA-RPC-001", "Reads data from a public blockchain RPC then executes it", "Reported loaders retrieve encrypted second-stage material from blockchain RPC endpoints.",
		regexp.MustCompile(`(?is)(eth_getTransactionByHash|getSignaturesForAddress|trongrid|bsc-dataseed)[^\n]{0,400}(eval|Function\s*\()`), SeverityHigh, ConfidenceMedium, CatSuspiciousCode},
}

var (
	hexIdent     = regexp.MustCompile(`\b_0x[0-9a-f]{4,6}\b`)
	sensitivePth = []string{".npmrc", ".ssh/id_", ".aws/credentials", "login data", "wallet.dat", ".config/gcloud", "keychain"}
)

func (StaticDetector) Detect(_ context.Context, f File) []Finding {
	if !isSource(f.Path) {
		return nil
	}
	var out []Finding
	for _, p := range staticPatterns {
		loc := p.re.FindIndex(f.Content)
		if loc == nil {
			continue
		}
		ln := lineOf(f.Content, loc[0])
		fd := Finding{
			RuleID: p.id, RuleVersion: ruleVersion, Category: p.cat, Severity: p.sev, Confidence: p.conf,
			Path: f.Path, LineStart: ln, LineEnd: ln, Title: p.title,
			Evidence:    "pattern " + p.id + " matched at line " + itoa(ln),
			Explanation: p.why + " This is a heuristic match, not a confirmed malware identification.",
			Remediation: "Review the code. If it is not understood and intentional, do not merge or deploy it.",
		}
		fd.seal(itoa(ln))
		out = append(out, fd)
	}
	if n := len(hexIdent.FindAll(f.Content, -1)); n >= 15 {
		fd := Finding{
			RuleID: "PC-STA-OBF-001", RuleVersion: ruleVersion, Category: CatObfuscation, Severity: SeverityMedium, Confidence: ConfidenceMedium,
			Path: f.Path, Title: "Obfuscator-style identifiers", Evidence: itoa(n) + " identifiers of the form _0xNNNN",
			Explanation: "Many _0x-style identifiers are characteristic of automated JavaScript obfuscators. Legitimate minified bundles rarely use them.",
			Remediation: "Confirm this file is a reviewed build artifact; source repositories should not normally contain obfuscated code.",
		}
		fd.seal("obf")
		out = append(out, fd)
	}
	lower := strings.ToLower(string(f.Content))
	hits := 0
	for _, s := range sensitivePth {
		if strings.Contains(lower, s) {
			hits++
		}
	}
	if hits >= 2 && regexp.MustCompile(`(?i)(fetch\(|axios|http\.request|https\.request|XMLHttpRequest|requests\.(post|put)|net\.Dial)`).Match(f.Content) {
		fd := Finding{
			RuleID: "PC-STA-CRED-001", RuleVersion: ruleVersion, Category: CatSuspiciousCode, Severity: SeverityHigh, Confidence: ConfidenceLow,
			Path: f.Path, Title: "Reads credential stores and makes network requests",
			Evidence:    "references " + itoa(hits) + " sensitive credential locations alongside network calls",
			Explanation: "Credential stealers read files such as .npmrc or SSH keys and send them over the network.",
			Remediation: "Verify the file's purpose. If unexpected, treat as a possible credential stealer.",
		}
		fd.seal("cred")
		out = append(out, fd)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
