package scanner

import (
	"bytes"
	"path"
	"strings"
)

func lineOf(content []byte, offset int) int {
	if offset > len(content) {
		offset = len(content)
	}
	return bytes.Count(content[:offset], []byte{'\n'}) + 1
}

func ext(p string) string  { return strings.ToLower(path.Ext(p)) }
func base(p string) string { return strings.ToLower(path.Base(p)) }

var sourceExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".tsx": true,
	".py": true, ".go": true, ".rs": true, ".sh": true, ".ps1": true, ".php": true,
	".rb": true, ".java": true, ".kt": true, ".swift": true, ".bat": true, ".cmd": true,
}

func isSource(p string) bool { return sourceExts[ext(p)] }

// mask hides the middle of a secret-like value.
func mask(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 6) + s[len(s)-2:]
}
