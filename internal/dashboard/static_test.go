package dashboard

import (
	"compress/gzip"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStaticHandlerCaching(t *testing.T) {
	sub, _ := fs.Sub(webFS, "web")
	h, err := staticHandler(sub)
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string, hdr map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := get("/app.js", nil)
	if w.Code != 200 || w.Header().Get("ETag") == "" || w.Header().Get("Cache-Control") != "no-cache" || w.Header().Get("Content-Encoding") != "" {
		t.Fatalf("plain: %d %v", w.Code, w.Header())
	}
	etag := w.Header().Get("ETag")
	if w2 := get("/app.js", map[string]string{"If-None-Match": etag}); w2.Code != http.StatusNotModified || w2.Body.Len() != 0 {
		t.Fatalf("revalidation should be 304 with no body, got %d (%d bytes)", w2.Code, w2.Body.Len())
	}
	wz := get("/app.js", map[string]string{"Accept-Encoding": "gzip"})
	if wz.Header().Get("Content-Encoding") != "gzip" || wz.Header().Get("ETag") == etag {
		t.Fatalf("gzip variant needs its own etag: %v", wz.Header())
	}
	zr, err := gzip.NewReader(wz.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(zr)
	if string(got) != w.Body.String() {
		t.Fatal("gzip body differs from plain body")
	}
	if get("/index.html", nil).Code != http.StatusNotFound {
		t.Error("index.html must only be served by the SPA route")
	}
	if get("/../../etc/passwd", nil).Code != http.StatusNotFound {
		t.Error("path escape not rejected")
	}
}
