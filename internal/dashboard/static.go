package dashboard

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// asset is one embedded static file, hashed and gzipped once at startup.
type asset struct {
	raw, gz   []byte
	etag, gzE string
	ctype     string
}

// staticHandler serves the embedded SPA files with a content-hash ETag and
// "no-cache" (always revalidate). Unchanged files answer 304 with no body, and a
// new deploy is picked up on the next load, so there are no stale-asset problems.
func staticHandler(sub fs.FS) (http.Handler, error) {
	files := map[string]*asset{}
	err := fs.WalkDir(sub, ".", func(p string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return err
		}
		b, err := fs.ReadFile(sub, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		a := &asset{raw: b, etag: `"` + hex.EncodeToString(sum[:12]) + `"`, ctype: ctypeFor(p)}
		a.gzE = a.etag[:len(a.etag)-1] + `-gz"`
		if strings.HasPrefix(a.ctype, "text/") || strings.Contains(a.ctype, "javascript") || strings.Contains(a.ctype, "svg") {
			var buf bytes.Buffer
			zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
			_, _ = zw.Write(b)
			_ = zw.Close()
			if buf.Len() < len(b) {
				a.gz = buf.Bytes()
			}
		}
		files[p] = a
		return nil
	})
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		a, ok := files[name]
		if !ok || name == "index.html" {
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", a.ctype)
		h.Set("Cache-Control", "no-cache")
		h.Add("Vary", "Accept-Encoding")
		body, tag := a.raw, a.etag
		if a.gz != nil && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			h.Set("Content-Encoding", "gzip")
			body, tag = a.gz, a.gzE
		}
		h.Set("ETag", tag)
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
	}), nil
}

func ctypeFor(p string) string {
	switch path.Ext(p) {
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".html":
		return "text/html; charset=utf-8"
	}
	return "application/octet-stream"
}
