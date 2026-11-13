// Package intel refreshes exact-match signatures from operator-configured feeds.
//
// Trust model: feeds are chosen by the operator, never by repository content.
// PolinChaser ships no third-party feed. A feed must declare its license, and the
// operator is responsible for having the right to use it. Feed signatures are exact
// indicators only (substring or whole-file SHA-256); they can never carry heuristic
// logic. A failed or invalid refresh keeps the previous signatures in place.
package intel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	MaxFeedBytes      = 2 << 20
	MaxSignatures     = 5000
	MinSubstringBytes = 8 // shorter substrings match too much innocent code
)

type FeedSignature struct {
	ID         string `json:"id"`
	Family     string `json:"family"`
	Substring  string `json:"substring,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Severity   string `json:"severity"`
	Provenance string `json:"provenance"`
}

type Feed struct {
	Format     int             `json:"format"`
	Name       string          `json:"name"`
	License    string          `json:"license"`
	Signatures []FeedSignature `json:"signatures"`
}

var (
	idRe     = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
	severity = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
)

// ParseFeed strictly validates a feed document. Unknown fields are rejected.
func ParseFeed(data []byte) (Feed, error) {
	var f Feed
	if len(data) > MaxFeedBytes {
		return f, fmt.Errorf("feed larger than %d bytes", MaxFeedBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return Feed{}, fmt.Errorf("invalid feed JSON: %w", err)
	}
	if dec.More() {
		return Feed{}, errors.New("trailing data after feed JSON")
	}
	if f.Format != 1 {
		return Feed{}, errors.New("unsupported feed format (want 1)")
	}
	if n := len(strings.TrimSpace(f.Name)); n == 0 || n > 100 {
		return Feed{}, errors.New("feed name is required (max 100 chars)")
	}
	if n := len(strings.TrimSpace(f.License)); n == 0 || n > 300 {
		return Feed{}, errors.New("feed license is required (max 300 chars)")
	}
	if len(f.Signatures) == 0 || len(f.Signatures) > MaxSignatures {
		return Feed{}, fmt.Errorf("feed must hold 1 to %d signatures", MaxSignatures)
	}
	seen := map[string]bool{}
	for i, s := range f.Signatures {
		bad := func(msg string) error { return fmt.Errorf("signature %d (%q): %s", i, truncate(s.ID, 40), msg) }
		if !idRe.MatchString(s.ID) {
			return Feed{}, bad("id must be 3-64 chars of A-Z a-z 0-9 . _ -")
		}
		if strings.HasPrefix(strings.ToUpper(s.ID), "PC-") {
			return Feed{}, bad("id prefix PC- is reserved for built-in rules")
		}
		if seen[s.ID] {
			return Feed{}, bad("duplicate id")
		}
		seen[s.ID] = true
		if n := len(strings.TrimSpace(s.Family)); n == 0 || n > 64 || !printable(s.Family) {
			return Feed{}, bad("family is required (max 64 printable chars)")
		}
		if n := len(strings.TrimSpace(s.Provenance)); n == 0 || n > 300 || !printable(s.Provenance) {
			return Feed{}, bad("provenance is required (max 300 printable chars)")
		}
		if !severity[s.Severity] {
			return Feed{}, bad("severity must be critical, high, medium, low or info")
		}
		switch {
		case s.Substring != "" && s.SHA256 != "":
			return Feed{}, bad("give substring or sha256, not both")
		case s.Substring != "":
			if len(s.Substring) < MinSubstringBytes || len(s.Substring) > 512 || !utf8.ValidString(s.Substring) {
				return Feed{}, bad(fmt.Sprintf("substring must be %d-512 bytes of valid UTF-8", MinSubstringBytes))
			}
		case s.SHA256 != "":
			if !sha256Re.MatchString(s.SHA256) {
				return Feed{}, bad("sha256 must be 64 lowercase hex characters")
			}
		default:
			return Feed{}, bad("substring or sha256 is required")
		}
	}
	return f, nil
}

func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
