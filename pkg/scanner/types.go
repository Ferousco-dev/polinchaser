// Package scanner is the PolinChaser detection engine. It has no dependency
// on GitHub, the database or any network service: it inspects bytes handed to
// it by a Source and never executes them.
package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Rank orders severities; higher is worse.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// Confidence is deliberately independent of Severity.
type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed_signature"
	ConfidenceHigh      Confidence = "high"
	ConfidenceMedium    Confidence = "medium"
	ConfidenceLow       Confidence = "low"
)

type Category string

const (
	CatKnownMalware     Category = "known_malware"
	CatSuspiciousCode   Category = "suspicious_code"
	CatObfuscation      Category = "obfuscation"
	CatCredentialExpose Category = "credential_exposure"
	CatMaliciousDep     Category = "malicious_dependency"
	CatVulnerableDep    Category = "vulnerable_dependency"
	CatSupplyChain      Category = "supply_chain_risk"
	CatPersistence      Category = "repository_persistence"
	CatCICD             Category = "cicd_compromise"
	CatSuspiciousBinary Category = "suspicious_binary"
	CatConfigRisk       Category = "configuration_risk"
	CatPolicy           Category = "policy_violation"
)

// Finding is one detection. Evidence is always masked/sanitised and short;
// it never contains a full secret or a payload body.
type Finding struct {
	RuleID      string     `json:"rule_id"`
	RuleVersion string     `json:"rule_version"`
	Category    Category   `json:"category"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Path        string     `json:"path"`
	LineStart   int        `json:"line_start,omitempty"`
	LineEnd     int        `json:"line_end,omitempty"`
	Title       string     `json:"title"`
	Evidence    string     `json:"evidence"`
	Explanation string     `json:"explanation"`
	Remediation string     `json:"remediation"`
	// Fingerprint is stable across scans for the same rule+path+evidence
	// digest, enabling deduplication and suppression.
	Fingerprint string `json:"fingerprint"`
}

func (f *Finding) seal(digestSource string) {
	h := sha256.Sum256([]byte(f.RuleID + "\x00" + f.Path + "\x00" + digestSource))
	f.Fingerprint = hex.EncodeToString(h[:16])
}

// File is a single in-memory file offered to detectors.
type File struct {
	Path    string
	Content []byte
	// Truncated is true when Content was cut at the size limit.
	Truncated bool
}

// Detector inspects one file. Implementations must be pure and must not
// perform I/O beyond reading the supplied File.
type Detector interface {
	ID() string
	Detect(ctx context.Context, f File) []Finding
}

type SkipReason string

const (
	SkipTooLarge   SkipReason = "file_too_large"
	SkipSymlink    SkipReason = "symlink"
	SkipLimit      SkipReason = "file_count_limit"
	SkipTotalSize  SkipReason = "total_size_limit"
	SkipUnreadable SkipReason = "unreadable"
	SkipBadPath    SkipReason = "unsafe_path"
	SkipDepLookup  SkipReason = "dependency_lookup_failed"
)

type Skipped struct {
	Path   string     `json:"path"`
	Reason SkipReason `json:"reason"`
}

type Status string

const (
	StatusClean      Status = "clean"
	StatusFindings   Status = "findings_detected"
	StatusIncomplete Status = "incomplete"
	StatusFailed     Status = "failed"
	StatusTimedOut   Status = "timed_out"
)

type Result struct {
	Status       Status    `json:"status"`
	Findings     []Finding `json:"findings"`
	FilesScanned int       `json:"files_scanned"`
	Skipped      []Skipped `json:"skipped"`
	Error        string    `json:"error,omitempty"`
}

// Highest returns the worst severity in the result.
func (r Result) Highest() Severity {
	best := SeverityInfo
	for _, f := range r.Findings {
		if f.Severity.Rank() > best.Rank() {
			best = f.Severity
		}
	}
	return best
}

func (r Result) String() string {
	return fmt.Sprintf("%s: %d findings, %d files, %d skipped", r.Status, len(r.Findings), r.FilesScanned, len(r.Skipped))
}

// Limits bound resource use. Zero values fall back to DefaultLimits.
type Limits struct {
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxFiles      int
}

var DefaultLimits = Limits{MaxFileBytes: 2 << 20, MaxTotalBytes: 256 << 20, MaxFiles: 50000}

func (l Limits) withDefaults() Limits {
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = DefaultLimits.MaxFileBytes
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = DefaultLimits.MaxTotalBytes
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = DefaultLimits.MaxFiles
	}
	return l
}
