package github

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func genKey(t *testing.T) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAppJWTClaimsAndSignature(t *testing.T) {
	k := genKey(t)
	now := time.Unix(1_700_000_000, 0)
	tok, err := AppJWT(42, k, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct{ Iat, Exp, Iss int64 }
	_ = json.Unmarshal(raw, &c)
	if c.Iss != 42 || c.Iat != now.Unix()-60 || c.Exp-now.Unix() != 540 {
		t.Fatalf("claims %+v", c)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("bad signature: %v", err)
	}
}

func TestParsePrivateKeyFormats(t *testing.T) {
	k := genKey(t)
	p1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	b8, _ := x509.MarshalPKCS8PrivateKey(k)
	p8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b8})
	for _, p := range [][]byte{p1, p8} {
		if _, err := ParsePrivateKey(p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ParsePrivateKey([]byte("nope")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func TestVerifySignature(t *testing.T) {
	body := []byte(`{"a":1}`)
	good := sign("s3cret", body)
	cases := map[string]struct {
		secret, header string
		body           []byte
		want           bool
	}{
		"valid":          {"s3cret", good, body, true},
		"wrong secret":   {"other", good, body, false},
		"tampered body":  {"s3cret", good, []byte(`{"a":2}`), false},
		"missing prefix": {"s3cret", strings.TrimPrefix(good, "sha256="), body, false},
		"sha1 header":    {"s3cret", "sha1=abcd", body, false},
		"not hex":        {"s3cret", "sha256=zzzz", body, false},
		"empty header":   {"s3cret", "", body, false},
		"empty secret":   {"", sign("", body), body, false},
	}
	for name, c := range cases {
		if got := VerifySignature(c.secret, c.body, c.header); got != c.want {
			t.Errorf("%s: got %v", name, got)
		}
	}
}

func TestInstallationTokenCachedAndPagination(t *testing.T) {
	k := genKey(t)
	var tokenCalls atomic.Int32
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		switch {
		case r.URL.Path == "/app/installations/7/access_tokens":
			tokenCalls.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"token": "inst-token", "expires_at": time.Now().Add(time.Hour)})
		case r.URL.Path == "/installation/repositories":
			n := 100
			if r.URL.Query().Get("page") == "2" {
				n = 3
			}
			repos := make([]Repo, n)
			for i := range repos {
				repos[i] = Repo{ID: int64(i + 1), FullName: "o/r"}
			}
			json.NewEncoder(w).Encode(map[string]any{"repositories": repos})
		}
	}))
	defer srv.Close()
	c := NewClient(1, k, srv.URL)
	repos, err := c.ListInstallationRepos(t.Context(), 7)
	if err != nil || len(repos) != 103 {
		t.Fatalf("%d %v", len(repos), err)
	}
	if _, err := c.InstallationToken(t.Context(), 7); err != nil || tokenCalls.Load() != 1 {
		t.Fatalf("token not cached: %d", tokenCalls.Load())
	}
	if !strings.HasPrefix(auth[0], "Bearer ") || auth[1] != "Bearer inst-token" {
		t.Fatalf("auth headers %v", auth)
	}
}

func TestAPIErrorDoesNotLeakToken(t *testing.T) {
	k := genKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) }))
	defer srv.Close()
	_, err := NewClient(1, k, srv.URL).InstallationToken(t.Context(), 1)
	ae, ok := err.(*APIError)
	if !ok || !ae.Retryable() {
		t.Fatalf("want retryable APIError, got %v", err)
	}
}

func TestValidRepoName(t *testing.T) {
	for _, ok := range []string{"acme/web", "a/b", "Ferousco-dev/polin_chaser.v2", "x.y/.github"} {
		if !ValidRepoName(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "acme", "acme/", "/web", "acme/web/extra", "../etc/passwd", "acme/..", "./x", "acme/web?x=1", "acme/web#frag", "ac me/web", "acme/we%2fb", "acme\\web", "-/x ", strings.Repeat("a", 101) + "/b"} {
		if ValidRepoName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
