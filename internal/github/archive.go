package github

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

// ArchiveLimits bound resource use when unpacking hostile archives.
type ArchiveLimits struct {
	MaxCompressed int64 // bytes read from the network
	MaxExpanded   int64 // total uncompressed bytes streamed (zip-bomb guard)
	MaxEntries    int
	MaxFileBytes  int64 // bytes kept per file; the rest is discarded
}

var DefaultArchiveLimits = ArchiveLimits{MaxCompressed: 200 << 20, MaxExpanded: 1 << 30, MaxEntries: 100000, MaxFileBytes: 2 << 20}

var ErrArchiveTooLarge = errors.New("github: archive exceeds safety limits")

type limitedCounter struct {
	r   io.Reader
	n   int64
	max int64
}

func (l *limitedCounter) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.n += int64(n)
	if l.n > l.max {
		return n, ErrArchiveTooLarge
	}
	return n, err
}

// ExtractTarGz reads a GitHub tarball entirely in memory. It never writes to
// disk, ignores links and special files, rejects unsafe paths, and aborts on
// expansion beyond the limits. The single top-level directory is stripped.
func ExtractTarGz(r io.Reader, lim ArchiveLimits) (scanner.PreparedSource, error) {
	out := scanner.PreparedSource{Files: map[string][]byte{}}
	comp := &limitedCounter{r: r, max: lim.MaxCompressed}
	gz, err := gzip.NewReader(comp)
	if err != nil {
		return out, fmt.Errorf("github: open gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(&limitedCounter{r: gz, max: lim.MaxExpanded})
	entries := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			if comp.n > comp.max { // a final oversized read can be consumed without surfacing the error
				return out, ErrArchiveTooLarge
			}
			return out, nil
		}
		if err != nil {
			return out, fmt.Errorf("github: read tar: %w", err)
		}
		if entries++; entries > lim.MaxEntries {
			return out, ErrArchiveTooLarge
		}
		switch h.Typeflag {
		case tar.TypeReg:
		case tar.TypeSymlink, tar.TypeLink:
			out.Skips = append(out.Skips, scanner.Skipped{Path: h.Name, Reason: scanner.SkipSymlink})
			continue
		default:
			continue // directories, pax headers, devices, fifos
		}
		_, rel, found := strings.Cut(h.Name, "/")
		if !found {
			continue
		}
		clean, ok := scanner.SafePath(rel)
		if !ok {
			out.Skips = append(out.Skips, scanner.Skipped{Path: rel, Reason: scanner.SkipBadPath})
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, lim.MaxFileBytes+1))
		if err != nil {
			return out, fmt.Errorf("github: read %q: %w", clean, err)
		}
		if int64(len(data)) > lim.MaxFileBytes {
			// Keep the head; the engine reports it as skipped/incomplete. Drain the rest.
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return out, err
			}
		}
		out.Files[clean] = data
	}
}
