package auth_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/Ferousco-dev/polinchaser/internal/auth"
	"github.com/Ferousco-dev/polinchaser/internal/testutil"
)

const (
	base       = "https://pc.example.com"
	setupToken = "setup-token-0123456789-0123456789-abcd"
)

var b64 = base64.RawURLEncoding

// device is a software WebAuthn authenticator (ES256, "none" attestation,
// user-verifying, discoverable credentials).
type device struct {
	key     *ecdsa.PrivateKey
	credID  []byte
	handle  []byte
	counter uint32
}

func newDevice() *device {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 32)
	rand.Read(id)
	return &device{key: k, credID: id}
}

func rpHash() [32]byte { return sha256.Sum256([]byte("pc.example.com")) }

func (d *device) register(t *testing.T, options map[string]any) []byte {
	pk := options["publicKey"].(map[string]any)
	d.handle, _ = b64.DecodeString(pk["user"].(map[string]any)["id"].(string))
	client, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": pk["challenge"], "origin": base})
	x, y := d.key.X.FillBytes(make([]byte, 32)), d.key.Y.FillBytes(make([]byte, 32))
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	h := rpHash()
	auth := append([]byte{}, h[:]...)
	auth = append(auth, 0x45) // UP | UV | AT
	auth = binary.BigEndian.AppendUint32(auth, 0)
	auth = append(auth, make([]byte, 16)...)
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(d.credID)))
	auth = append(auth, d.credID...)
	auth = append(auth, cose...)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth})
	out, _ := json.Marshal(map[string]any{"id": b64.EncodeToString(d.credID), "rawId": b64.EncodeToString(d.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(client), "attestationObject": b64.EncodeToString(att), "transports": []string{"internal"}}})
	return out
}

func (d *device) assert(t *testing.T, options map[string]any, origin string) []byte {
	pk := options["publicKey"].(map[string]any)
	d.counter++
	client, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": pk["challenge"], "origin": origin})
	h := rpHash()
	auth := append([]byte{}, h[:]...)
	auth = append(auth, 0x05) // UP | UV
	auth = binary.BigEndian.AppendUint32(auth, d.counter)
	cd := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, auth...), cd[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, d.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{"id": b64.EncodeToString(d.credID), "rawId": b64.EncodeToString(d.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(client), "authenticatorData": b64.EncodeToString(auth),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(d.handle)}})
	return out
}

type env struct {
	t   *testing.T
	svc *auth.Service
	h   *auth.HTTP
	mux *http.ServeMux
	now time.Time
}

func newEnv(t *testing.T) *env {
	pool := testutil.Pool(t)
	svc, err := auth.New(pool, base, setupToken)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, svc: svc, now: time.Now()}
	svc.Now = func() time.Time { return e.now }
	e.h = &auth.HTTP{Svc: svc, BaseURL: base, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Limiter: auth.NewLimiter(1000, time.Minute)}
	e.mux = http.NewServeMux()
	e.h.Routes(e.mux)
	e.mux.Handle("GET /api/secret", e.h.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("secret")) })))
	return e
}

func (e *env) do(method, path string, body []byte, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func (e *env) post(path string, v any, cookie *http.Cookie) *httptest.ResponseRecorder {
	b, _ := json.Marshal(v)
	return e.do("POST", path, b, cookie, base)
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("bad json %q", rec.Body)
	}
	return m
}

// setup registers the first device using the operator setup token.
func (e *env) setup(d *device) {
	rec := e.post("/api/auth/setup/begin", map[string]string{"token": setupToken}, nil)
	if rec.Code != 200 {
		e.t.Fatalf("setup begin: %d %s", rec.Code, rec.Body)
	}
	m := decode(e.t, rec)
	body := d.register(e.t, m["options"].(map[string]any))
	if rec := e.do("POST", "/api/auth/setup/finish?name=MacBook&cid="+m["challenge_id"].(string), body, nil, base); rec.Code != 200 {
		e.t.Fatalf("setup finish: %d %s", rec.Code, rec.Body)
	}
}

func (e *env) login(d *device) (*http.Cookie, *httptest.ResponseRecorder) {
	rec := e.post("/api/auth/login/begin", nil, nil)
	m := decode(e.t, rec)
	body := d.assert(e.t, m["options"].(map[string]any), base)
	rec = e.do("POST", "/api/auth/login/finish?cid="+m["challenge_id"].(string), body, nil, base)
	for _, c := range rec.Result().Cookies() {
		return c, rec
	}
	return nil, rec
}

func TestSetupRequiresOperatorTokenAndClosesAfterFirstPasskey(t *testing.T) {
	e := newEnv(t)
	if rec := e.post("/api/auth/setup/begin", map[string]string{"token": "wrong"}, nil); rec.Code != 403 {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	if rec := e.post("/api/auth/setup/begin", map[string]string{"token": ""}, nil); rec.Code != 403 {
		t.Fatalf("empty token: %d", rec.Code)
	}
	st := decode(t, e.do("GET", "/api/auth/status", nil, nil, ""))
	if st["initialized"] != false || st["setup_available"] != true {
		t.Fatalf("%v", st)
	}
	e.setup(newDevice())
	if rec := e.post("/api/auth/setup/begin", map[string]string{"token": setupToken}, nil); rec.Code != 403 {
		t.Fatalf("setup must close after first passkey, got %d", rec.Code)
	}
	st = decode(t, e.do("GET", "/api/auth/status", nil, nil, ""))
	if st["initialized"] != true || st["setup_available"] != false {
		t.Fatalf("%v", st)
	}
}

func TestSetupDisabledWithoutConfiguredToken(t *testing.T) {
	e := newEnv(t)
	e.svc.SetupToken = ""
	if rec := e.post("/api/auth/setup/begin", map[string]string{"token": ""}, nil); rec.Code != 403 {
		t.Fatalf("empty configured token must never match: %d", rec.Code)
	}
}

func TestPasskeyLoginSessionAndLogout(t *testing.T) {
	e := newEnv(t)
	d := newDevice()
	e.setup(d)
	if rec := e.do("GET", "/api/secret", nil, nil, ""); rec.Code != 401 {
		t.Fatal("protected route open without session")
	}
	cookie, rec := e.login(d)
	if rec.Code != 200 || cookie == nil {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	if cookie.Name != "__Host-pc_session" || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("weak cookie: %+v", cookie)
	}
	if rec := e.do("GET", "/api/secret", nil, cookie, ""); rec.Code != 200 {
		t.Fatalf("session rejected: %d", rec.Code)
	}
	var stored int
	e.svc.Pool.QueryRow(t.Context(), `SELECT count(*) FROM sessions WHERE token_hash = $1`, []byte(cookie.Value)).Scan(&stored)
	if stored != 0 {
		t.Fatal("raw session token stored in DB")
	}
	if rec := e.do("POST", "/api/auth/logout", nil, cookie, base); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	if rec := e.do("GET", "/api/secret", nil, cookie, ""); rec.Code != 401 {
		t.Fatal("session survived logout")
	}
}

func TestLoginRejections(t *testing.T) {
	e := newEnv(t)
	d := newDevice()
	e.setup(d)
	// Unknown device (valid signature, not registered).
	other := newDevice()
	other.handle = d.handle
	m := decode(t, e.post("/api/auth/login/begin", nil, nil))
	rec := e.do("POST", "/api/auth/login/finish?cid="+m["challenge_id"].(string), other.assert(t, m["options"].(map[string]any), base), nil, base)
	if rec.Code != 401 {
		t.Fatalf("unregistered device: %d", rec.Code)
	}
	// Wrong origin inside clientDataJSON (phishing site relay).
	m = decode(t, e.post("/api/auth/login/begin", nil, nil))
	rec = e.do("POST", "/api/auth/login/finish?cid="+m["challenge_id"].(string), d.assert(t, m["options"].(map[string]any), "https://evil.example"), nil, base)
	if rec.Code != 401 {
		t.Fatalf("phished origin accepted: %d", rec.Code)
	}
	// Challenge is single-use (replay).
	m = decode(t, e.post("/api/auth/login/begin", nil, nil))
	body := d.assert(t, m["options"].(map[string]any), base)
	cid := m["challenge_id"].(string)
	if rec := e.do("POST", "/api/auth/login/finish?cid="+cid, body, nil, base); rec.Code != 200 {
		t.Fatalf("legit login failed: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/api/auth/login/finish?cid="+cid, body, nil, base); rec.Code == 200 {
		t.Fatalf("replayed assertion accepted: %d", rec.Code)
	}
	// Expired challenge.
	m = decode(t, e.post("/api/auth/login/begin", nil, nil))
	body = d.assert(t, m["options"].(map[string]any), base)
	e.now = e.now.Add(auth.ChallengeTTL + time.Second)
	if rec := e.do("POST", "/api/auth/login/finish?cid="+m["challenge_id"].(string), body, nil, base); rec.Code == 200 {
		t.Fatalf("expired challenge accepted: %d", rec.Code)
	}
	// Garbage.
	if rec := e.do("POST", "/api/auth/login/finish?cid=nope", []byte("{}"), nil, base); rec.Code == 200 {
		t.Fatal(rec.Code)
	}
}

func TestClonedAuthenticatorRejected(t *testing.T) {
	e := newEnv(t)
	d := newDevice()
	e.setup(d)
	d.counter = 10
	if _, rec := e.login(d); rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
	d.counter = 3 // regressed counter => clone
	if _, rec := e.login(d); rec.Code != 401 {
		t.Fatalf("cloned authenticator accepted: %d", rec.Code)
	}
}

func TestSessionExpiry(t *testing.T) {
	e := newEnv(t)
	d := newDevice()
	e.setup(d)
	cookie, _ := e.login(d)
	e.now = e.now.Add(auth.SessionIdle - time.Minute)
	if rec := e.do("GET", "/api/secret", nil, cookie, ""); rec.Code != 200 {
		t.Fatal("active session rejected")
	}
	e.now = e.now.Add(auth.SessionIdle + time.Minute)
	if rec := e.do("GET", "/api/secret", nil, cookie, ""); rec.Code != 401 {
		t.Fatal("idle session not expired")
	}
	cookie, _ = e.login(d)
	for i := 0; i < 8; i++ { // stay active past the absolute lifetime
		e.now = e.now.Add(90 * time.Minute)
		e.do("GET", "/api/secret", nil, cookie, "")
	}
	if rec := e.do("GET", "/api/secret", nil, cookie, ""); rec.Code != 401 {
		t.Fatal("absolute lifetime not enforced")
	}
}

func TestOriginGuardBlocksCrossSiteWrites(t *testing.T) {
	e := newEnv(t)
	d := newDevice()
	e.setup(d)
	cookie, _ := e.login(d)
	for _, origin := range []string{"", "https://evil.example", "http://pc.example.com"} {
		if rec := e.do("POST", "/api/auth/enroll-link", nil, cookie, origin); rec.Code != 403 {
			t.Errorf("origin %q accepted: %d", origin, rec.Code)
		}
	}
	if rec := e.do("POST", "/api/auth/enroll-link", nil, cookie, base); rec.Code != 200 {
		t.Fatal("same-origin write rejected")
	}
}

func TestEnrollmentLinkAddsSecondDeviceOnceOnly(t *testing.T) {
	e := newEnv(t)
	mac := newDevice()
	e.setup(mac)
	cookie, _ := e.login(mac)
	link := decode(t, e.do("POST", "/api/auth/enroll-link", nil, cookie, base))
	u := link["url"].(string)
	if !strings.HasPrefix(u, base+"/enroll#") {
		t.Fatalf("token must be in the fragment: %s", u)
	}
	token := strings.TrimPrefix(u, base+"/enroll#")
	var raw int
	e.svc.Pool.QueryRow(t.Context(), `SELECT count(*) FROM enrollment_tokens WHERE token_hash=$1`, []byte(token)).Scan(&raw)
	if raw != 0 {
		t.Fatal("raw enrollment token stored")
	}
	phone := newDevice()
	begin := decode(t, e.post("/api/auth/enroll/begin", map[string]string{"token": token}, nil))
	body := phone.register(t, begin["options"].(map[string]any))
	if rec := e.do("POST", "/api/auth/enroll/finish?name=iPhone&cid="+begin["challenge_id"].(string), body, nil, base); rec.Code != 200 {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
	if _, rec := e.login(phone); rec.Code != 200 {
		t.Fatalf("phone cannot log in: %d", rec.Code)
	}
	// Link is now spent.
	if rec := e.post("/api/auth/enroll/begin", map[string]string{"token": token}, nil); rec.Code != 403 {
		t.Fatalf("used link accepted: %d", rec.Code)
	}
	var n int
	e.svc.Pool.QueryRow(t.Context(), `SELECT count(*) FROM passkeys`).Scan(&n)
	if n != 2 {
		t.Fatalf("passkeys=%d", n)
	}
}

func TestEnrollmentLinkExpiresAndRaceCreatesOnePasskey(t *testing.T) {
	e := newEnv(t)
	e.setup(newDevice())
	tok, _, err := e.svc.CreateEnrollLink(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	// Two devices begin with the same valid link, then both try to finish.
	a, b := newDevice(), newDevice()
	ba := decode(t, e.post("/api/auth/enroll/begin", map[string]string{"token": tok}, nil))
	bb := decode(t, e.post("/api/auth/enroll/begin", map[string]string{"token": tok}, nil))
	ra := e.do("POST", "/api/auth/enroll/finish?cid="+ba["challenge_id"].(string), a.register(t, ba["options"].(map[string]any)), nil, base)
	rb := e.do("POST", "/api/auth/enroll/finish?cid="+bb["challenge_id"].(string), b.register(t, bb["options"].(map[string]any)), nil, base)
	if (ra.Code == 200) == (rb.Code == 200) {
		t.Fatalf("exactly one must win: %d %d", ra.Code, rb.Code)
	}
	tok2, _, _ := e.svc.CreateEnrollLink(t.Context(), 1)
	e.now = e.now.Add(auth.EnrollLinkTTL + time.Second)
	if rec := e.post("/api/auth/enroll/begin", map[string]string{"token": tok2}, nil); rec.Code != 403 {
		t.Fatalf("expired link accepted: %d", rec.Code)
	}
	if rec := e.post("/api/auth/enroll/begin", map[string]string{"token": "garbage"}, nil); rec.Code != 403 {
		t.Fatal("garbage token accepted")
	}
}

func TestEnrollLinkRequiresSessionAndLastPasskeyProtected(t *testing.T) {
	e := newEnv(t)
	d := newDevice()
	e.setup(d)
	if rec := e.do("POST", "/api/auth/enroll-link", nil, nil, base); rec.Code != 401 {
		t.Fatalf("anonymous may not mint links: %d", rec.Code)
	}
	cookie, _ := e.login(d)
	if rec := e.do("DELETE", "/api/auth/passkeys/1", nil, cookie, base); rec.Code != 409 {
		t.Fatalf("last passkey removable: %d", rec.Code)
	}
	// Add a second, then revoke the first: its sessions must die.
	tok, _, _ := e.svc.CreateEnrollLink(t.Context(), 1)
	p := newDevice()
	bg := decode(t, e.post("/api/auth/enroll/begin", map[string]string{"token": tok}, nil))
	e.do("POST", "/api/auth/enroll/finish?cid="+bg["challenge_id"].(string), p.register(t, bg["options"].(map[string]any)), nil, base)
	if rec := e.do("DELETE", "/api/auth/passkeys/1", nil, cookie, base); rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("GET", "/api/secret", nil, cookie, ""); rec.Code != 401 {
		t.Fatal("revoked passkey's session still valid")
	}
}

func TestAuthRateLimit(t *testing.T) {
	e := newEnv(t)
	e.h.Limiter = auth.NewLimiter(3, time.Minute)
	e.mux = http.NewServeMux()
	e.h.Routes(e.mux)
	codes := []int{}
	for i := 0; i < 5; i++ {
		codes = append(codes, e.post("/api/auth/setup/begin", map[string]string{"token": "guess"}, nil).Code)
	}
	if codes[3] != 429 || codes[4] != 429 {
		t.Fatalf("not rate limited: %v", codes)
	}
}

func TestClientIPOnlyTrustsConfiguredProxyHops(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.9:1234"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.5")
	if got := auth.ClientIP(r, 0); got != "10.0.0.9" {
		t.Fatalf("spoofable by default: %s", got)
	}
	if got := auth.ClientIP(r, 1); got != "203.0.113.5" {
		t.Fatalf("hops=1: %s", got)
	}
	r.Header.Set("X-Forwarded-For", "not-an-ip")
	if got := auth.ClientIP(r, 1); got != "10.0.0.9" {
		t.Fatalf("garbage XFF: %s", got)
	}
}
