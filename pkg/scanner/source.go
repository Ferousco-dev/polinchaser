package scanner

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Source yields files to scan. Implementations decide how files are obtained
// (local directory, GitHub tarball, upload) but must enforce path safety.
type Source interface {
	// Walk calls fn for every readable file. Skips are reported via skip.
	Walk(ctx context.Context, lim Limits, fn func(File) error, skip func(Skipped)) error
}

// SafePath rejects absolute paths, traversal and NUL bytes, and returns the
// cleaned slash-separated relative path.
func SafePath(p string) (string, bool) {
	if p == "" || strings.ContainsRune(p, 0) || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return "", false
	}
	c := path.Clean(p)
	if c == "." || c == ".." || strings.HasPrefix(c, "../") {
		return "", false
	}
	return c, true
}

// MemorySource is used by tests and by callers that already hold file bytes
// (e.g. changed files fetched from the GitHub API).
type MemorySource map[string][]byte

func (m MemorySource) Walk(ctx context.Context, lim Limits, fn func(File) error, skip func(Skipped)) error {
	lim = lim.withDefaults()
	n, total := 0, int64(0)
	for p, b := range m {
		if err := ctx.Err(); err != nil {
			return err
		}
		clean, ok := SafePath(p)
		if !ok {
			skip(Skipped{p, SkipBadPath})
			continue
		}
		if n >= lim.MaxFiles {
			skip(Skipped{clean, SkipLimit})
			continue
		}
		if total+int64(len(b)) > lim.MaxTotalBytes {
			skip(Skipped{clean, SkipTotalSize})
			continue
		}
		f := File{Path: clean, Content: b}
		if int64(len(b)) > lim.MaxFileBytes {
			f.Content, f.Truncated = b[:lim.MaxFileBytes], true
		}
		n++
		total += int64(len(f.Content))
		if err := fn(f); err != nil {
			return err
		}
	}
	return nil
}

// DirSource scans a directory on disk. Symlinks are never followed.
type DirSource struct{ Root string }

func (d DirSource) Walk(ctx context.Context, lim Limits, fn func(File) error, skip func(Skipped)) error {
	lim = lim.withDefaults()
	n, total := 0, int64(0)
	return filepath.WalkDir(d.Root, func(p string, e fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		rel, rerr := filepath.Rel(d.Root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if err != nil {
			skip(Skipped{rel, SkipUnreadable})
			return nil
		}
		if e.IsDir() {
			if rel == ".git" || strings.HasSuffix(rel, "/.git") {
				return filepath.SkipDir
			}
			return nil
		}
		if e.Type()&fs.ModeSymlink != 0 {
			skip(Skipped{rel, SkipSymlink})
			return nil
		}
		if !e.Type().IsRegular() {
			return nil
		}
		if n >= lim.MaxFiles {
			skip(Skipped{rel, SkipLimit})
			return nil
		}
		info, err := e.Info()
		if err != nil {
			skip(Skipped{rel, SkipUnreadable})
			return nil
		}
		if total+min(info.Size(), lim.MaxFileBytes) > lim.MaxTotalBytes {
			skip(Skipped{rel, SkipTotalSize})
			return nil
		}
		f := File{Path: rel}
		fh, err := os.Open(p)
		if err != nil {
			skip(Skipped{rel, SkipUnreadable})
			return nil
		}
		defer fh.Close()
		b, err := io.ReadAll(io.LimitReader(fh, lim.MaxFileBytes+1))
		if err != nil {
			skip(Skipped{rel, SkipUnreadable})
			return nil
		}
		if int64(len(b)) > lim.MaxFileBytes {
			b, f.Truncated = b[:lim.MaxFileBytes], true
		}
		f.Content = b
		n++
		total += int64(len(b))
		return fn(f)
	})
}

// PreparedSource wraps files obtained elsewhere (e.g. an extracted archive)
// together with skips discovered during preparation, so those skips make the
// scan "incomplete" rather than being silently lost.
type PreparedSource struct {
	Files map[string][]byte
	Skips []Skipped
}

func (p PreparedSource) Walk(ctx context.Context, lim Limits, fn func(File) error, skip func(Skipped)) error {
	for _, s := range p.Skips {
		skip(s)
	}
	return MemorySource(p.Files).Walk(ctx, lim, fn, skip)
}
