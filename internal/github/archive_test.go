package github

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

type entry struct {
	name, body string
	typ        byte
	link       string
}

func mkTarGz(t *testing.T, es []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range es {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Mode: 0o644, Size: int64(len(e.body)), Linkname: e.link}
		if typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestExtractStripsRootAndFiltersUnsafe(t *testing.T) {
	data := mkTarGz(t, []entry{
		{name: "repo-abc/", typ: tar.TypeDir}, {name: "repo-abc/src/a.js", body: "ok"},
		{name: "repo-abc/../../etc/passwd", body: "x"},
		{name: "repo-abc/link", typ: tar.TypeSymlink, link: "/etc/passwd"},
		{name: "repo-abc/hard", typ: tar.TypeLink, link: "src/a.js"},
	})
	got, err := ExtractTarGz(bytes.NewReader(data), DefaultArchiveLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 1 || string(got.Files["src/a.js"]) != "ok" {
		t.Fatalf("files: %v", got.Files)
	}
	reasons := map[scanner.SkipReason]int{}
	for _, s := range got.Skips {
		reasons[s.Reason]++
	}
	if reasons[scanner.SkipSymlink] != 2 || reasons[scanner.SkipBadPath] < 1 {
		t.Fatalf("skips: %+v", got.Skips)
	}
}

func TestExtractZipBombAborted(t *testing.T) {
	data := mkTarGz(t, []entry{{name: "r/big.txt", body: strings.Repeat("A", 5<<20)}})
	lim := ArchiveLimits{MaxCompressed: 1 << 20, MaxExpanded: 1 << 20, MaxEntries: 10, MaxFileBytes: 1 << 20}
	if len(data) > 1<<20 {
		t.Fatal("fixture should compress well")
	}
	if _, err := ExtractTarGz(bytes.NewReader(data), lim); !errors.Is(err, ErrArchiveTooLarge) {
		t.Fatalf("want ErrArchiveTooLarge, got %v", err)
	}
}

func TestExtractEntryAndCompressedLimits(t *testing.T) {
	var es []entry
	for i := 0; i < 20; i++ {
		es = append(es, entry{name: "r/f" + string(rune('a'+i)), body: "x"})
	}
	data := mkTarGz(t, es)
	if _, err := ExtractTarGz(bytes.NewReader(data), ArchiveLimits{MaxCompressed: 1 << 20, MaxExpanded: 1 << 20, MaxEntries: 5, MaxFileBytes: 10}); !errors.Is(err, ErrArchiveTooLarge) {
		t.Fatalf("entries: %v", err)
	}
	if _, err := ExtractTarGz(bytes.NewReader(data), ArchiveLimits{MaxCompressed: 10, MaxExpanded: 1 << 20, MaxEntries: 100, MaxFileBytes: 10}); err == nil {
		t.Fatal("compressed limit not enforced")
	}
}

func TestExtractTruncatesLargeFileAndKeepsGoing(t *testing.T) {
	data := mkTarGz(t, []entry{{name: "r/big.js", body: strings.Repeat("A", 100)}, {name: "r/b.js", body: "ok"}})
	got, err := ExtractTarGz(bytes.NewReader(data), ArchiveLimits{MaxCompressed: 1 << 20, MaxExpanded: 1 << 20, MaxEntries: 10, MaxFileBytes: 10})
	if err != nil || string(got.Files["b.js"]) != "ok" || len(got.Files["big.js"]) != 11 {
		t.Fatalf("%v %v", err, len(got.Files["big.js"]))
	}
}

func TestExtractRejectsNonGzip(t *testing.T) {
	if _, err := ExtractTarGz(strings.NewReader("not gzip"), DefaultArchiveLimits); err == nil {
		t.Fatal("accepted non-gzip")
	}
}

func TestRedirectAllowlist(t *testing.T) {
	base, _ := url.Parse("https://api.github.com")
	for u, want := range map[string]bool{
		"https://codeload.github.com/x":            true,
		"https://objects.githubusercontent.com/x":  true,
		"https://api.github.com/x":                 true,
		"http://codeload.github.com/x":             false,
		"https://169.254.169.254/latest/meta-data": false,
		"https://evil.example.com/x":               false,
		"https://github.com.evil.example/x":        false,
		"https://notgithubusercontent.com/x":       false,
		"https://localhost:5432/":                  false,
	} {
		p, _ := url.Parse(u)
		if got := allowedDownloadHost(p, base); got != want {
			t.Errorf("%s: got %v", u, got)
		}
	}
}
