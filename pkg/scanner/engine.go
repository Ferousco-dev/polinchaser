package scanner

import (
	"context"
	"errors"
	"sort"
)

// Engine runs detectors over a Source.
type Engine struct {
	Detectors []Detector
	Limits    Limits
}

// New returns an Engine with the built-in detectors and the given rules.
func New(rules RuleSet) *Engine {
	return &Engine{Detectors: []Detector{
		NewSignatureDetector(rules),
		HiddenPayloadDetector{},
		StaticDetector{},
		PersistenceDetector{},
		SecretsDetector{},
		DependencyDetector{},
		ActionsDetector{},
	}}
}

// Scan never reports a failed or cut-short scan as clean.
func (e *Engine) Scan(ctx context.Context, src Source) Result {
	res := Result{Status: StatusClean}
	skip := func(s Skipped) { res.Skipped = append(res.Skipped, s) }
	err := src.Walk(ctx, e.Limits, func(f File) error {
		res.FilesScanned++
		for _, d := range e.Detectors {
			if err := ctx.Err(); err != nil {
				return err
			}
			res.Findings = append(res.Findings, d.Detect(ctx, f)...)
		}
		if f.Truncated {
			res.Skipped = append(res.Skipped, Skipped{f.Path, SkipTooLarge})
		}
		return nil
	}, skip)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		res.Status, res.Error = StatusTimedOut, err.Error()
	case err != nil:
		res.Status, res.Error = StatusFailed, err.Error()
	}
	res.Findings = dedupe(res.Findings)
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.Path < b.Path
	})
	if res.Status == StatusClean {
		switch {
		case len(res.Skipped) > 0:
			res.Status = StatusIncomplete
		}
		if len(res.Findings) > 0 {
			res.Status = StatusFindings
		}
	}
	return res
}

func dedupe(in []Finding) []Finding {
	seen := map[string]bool{}
	out := in[:0]
	for _, f := range in {
		if seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		out = append(out, f)
	}
	return out
}
