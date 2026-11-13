package scanner

import (
	"bytes"
	"context"
	"fmt"
)

// HiddenPayloadDetector finds payloads concealed inside otherwise ordinary
// files: blank-line gaps, NUL injection, disguised/polyglot assets.
type HiddenPayloadDetector struct{}

func (HiddenPayloadDetector) ID() string { return "hidden_payload" }

const (
	blankGapMin    = 40   // consecutive blank lines before content is "hidden"
	denseLineBytes = 1500 // a single line this long after a gap is dense code
)

var assetMagic = map[string][][]byte{
	".woff2": {[]byte("wOF2")}, ".woff": {[]byte("wOFF")},
	".ttf": {{0, 1, 0, 0}, []byte("true")}, ".otf": {[]byte("OTTO")},
	".png": {{0x89, 'P', 'N', 'G'}}, ".jpg": {{0xFF, 0xD8}}, ".jpeg": {{0xFF, 0xD8}},
	".gif": {[]byte("GIF8")}, ".pdf": {[]byte("%PDF")},
}

var execMagic = [][]byte{
	[]byte("MZ"), {0x7f, 'E', 'L', 'F'}, {0xCF, 0xFA, 0xED, 0xFE}, {0xCE, 0xFA, 0xED, 0xFE}, {0xCA, 0xFE, 0xBA, 0xBE},
}

func (HiddenPayloadDetector) Detect(_ context.Context, f File) []Finding {
	var out []Finding
	e := ext(f.Path)

	if want, ok := assetMagic[e]; ok && len(f.Content) > 0 {
		matches := false
		for _, m := range want {
			if bytes.HasPrefix(f.Content, m) {
				matches = true
			}
		}
		if !matches {
			fd := Finding{
				RuleID: "PC-HID-MAGIC-001", RuleVersion: ruleVersion, Category: CatSuspiciousBinary,
				Severity: SeverityHigh, Confidence: ConfidenceMedium, Path: f.Path,
				Title:       "File content does not match its extension",
				Evidence:    fmt.Sprintf("extension %s but header bytes do not match the expected format", e),
				Explanation: "Asset files that do not begin with the expected magic bytes may be disguised scripts or executables (for example fake font files).",
				Remediation: "Inspect the file out-of-band without executing it. Remove it if it is not a genuine asset.",
			}
			if looksLikeScript(f.Content) {
				fd.Confidence, fd.Title = ConfidenceHigh, "Asset file contains script text"
			}
			if hasExecMagic(f.Content) {
				fd.Severity, fd.Confidence, fd.Title = SeverityCritical, ConfidenceHigh, "Executable binary disguised as an asset"
			}
			fd.seal(e)
			out = append(out, fd)
		}
	} else if !isBinaryExt(e) && hasExecMagic(f.Content) {
		fd := Finding{
			RuleID: "PC-HID-EXEC-001", RuleVersion: ruleVersion, Category: CatSuspiciousBinary,
			Severity: SeverityMedium, Confidence: ConfidenceMedium, Path: f.Path,
			Title: "Executable binary header in unexpected file", Evidence: "executable magic bytes at file start",
			Explanation: "The file has an executable header but a non-executable extension.",
			Remediation: "Confirm the file is expected. Remove committed binaries that are not intentional.",
		}
		fd.seal("exec")
		out = append(out, fd)
	}

	if !isSource(f.Path) && !isConfigExt(e) {
		return out
	}
	if bytes.IndexByte(f.Content, 0) >= 0 {
		fd := Finding{
			RuleID: "PC-HID-NUL-001", RuleVersion: ruleVersion, Category: CatSuspiciousCode,
			Severity: SeverityMedium, Confidence: ConfidenceMedium, Path: f.Path,
			Title: "NUL byte inside text file", Evidence: "NUL byte found in a text/source file",
			Explanation: "NUL bytes inside source files can truncate review tooling and hide appended content.",
			Remediation: "Inspect the raw bytes of the file and remove injected content.",
		}
		fd.seal("nul")
		out = append(out, fd)
	}
	if line, dense, ok := blankGapPayload(f.Content); ok {
		fd := Finding{
			RuleID: "PC-HID-GAP-001", RuleVersion: ruleVersion, Category: CatObfuscation,
			Severity: SeverityHigh, Confidence: ConfidenceMedium, Path: f.Path,
			LineStart: line, LineEnd: line,
			Title:       "Code hidden after a long run of blank lines",
			Evidence:    fmt.Sprintf("content begins at line %d after >=%d consecutive blank lines", line, blankGapMin),
			Explanation: "A long vertical gap followed by code pushes the content out of view in editors and diffs. This is a known concealment technique for appended payloads.",
			Remediation: "Open the file at the reported line and verify the code is intentional. If not, remove it and treat the repository as potentially compromised.",
		}
		if dense {
			fd.Confidence = ConfidenceHigh
			fd.Evidence += " and is a single very long line"
		}
		fd.seal("gap")
		out = append(out, fd)
	}
	return out
}

// blankGapPayload returns the line where content resumes after a long blank gap.
func blankGapPayload(b []byte) (line int, dense, ok bool) {
	blank, ln := 0, 0
	for len(b) > 0 {
		ln++
		i := bytes.IndexByte(b, '\n')
		var l []byte
		if i < 0 {
			l, b = b, nil
		} else {
			l, b = b[:i], b[i+1:]
		}
		if len(bytes.TrimSpace(l)) == 0 {
			blank++
			continue
		}
		if blank >= blankGapMin {
			return ln, len(l) >= denseLineBytes, true
		}
		blank = 0
	}
	return 0, false, false
}

func looksLikeScript(b []byte) bool {
	h := b
	if len(h) > 4096 {
		h = h[:4096]
	}
	for _, m := range []string{"function", "eval(", "require(", "var ", "const ", "<?php", "#!/", "import "} {
		if bytes.Contains(h, []byte(m)) {
			return true
		}
	}
	return false
}

func hasExecMagic(b []byte) bool {
	for _, m := range execMagic {
		if bytes.HasPrefix(b, m) {
			return true
		}
	}
	return false
}

func isBinaryExt(e string) bool {
	switch e {
	case ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".class", ".jar", ".wasm", ".a", ".node":
		return true
	}
	return false
}

func isConfigExt(e string) bool {
	switch e {
	case ".json", ".yml", ".yaml", ".toml", ".mjs", ".cjs", ".conf", ".ini":
		return true
	}
	return false
}
