package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// webauthnRequest is the *http.Request go-webauthn parses the ceremony from.
type webauthnRequest = *http.Request

type ctxKey struct{}

// Session identity attached to authenticated requests.
type Identity struct {
	PasskeyID int64
	Token     string
}

func IdentityFrom(ctx context.Context) (Identity, bool) {
	i, ok := ctx.Value(ctxKey{}).(Identity)
	return i, ok
}

// AuditFunc records security-relevant events.
type AuditFunc func(ctx context.Context, actor, action, target string)

type HTTP struct {
	Svc        *Service
	BaseURL    string
	Log        *slog.Logger
	Audit      AuditFunc
	Limiter    *Limiter
	TrustedHop int
}

func (h *HTTP) secure() bool { return strings.HasPrefix(h.BaseURL, "https://") }

// CookieName uses the __Host- prefix whenever HTTPS makes that possible.
func (h *HTTP) CookieName() string {
	if h.secure() {
		return "__Host-pc_session"
	}
	return "pc_session"
}

func (h *HTTP) origin() string {
	u, _ := url.Parse(h.BaseURL)
	return u.Scheme + "://" + u.Host
}

func (h *HTTP) audit(ctx context.Context, actor, action, target string) {
	if h.Audit != nil {
		h.Audit(ctx, actor, action, target)
	}
}

// OriginGuard rejects state-changing requests whose Origin is not this site.
// Together with SameSite=Strict cookies this is the CSRF defence.
func (h *HTTP) OriginGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if r.Header.Get("Origin") != h.origin() {
				jsonErr(w, http.StatusForbidden, "bad origin")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Require wraps a handler so it only runs for a valid session.
func (h *HTTP) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(h.CookieName())
		if err != nil {
			jsonErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		id, err := h.Svc.Session(r.Context(), c.Value)
		if err != nil {
			h.clearCookie(w)
			jsonErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, Identity{PasskeyID: id, Token: c.Value})))
	})
}

func (h *HTTP) setCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: h.CookieName(), Value: token, Path: "/", MaxAge: int(SessionTTL.Seconds()),
		HttpOnly: true, Secure: h.secure(), SameSite: http.SameSiteStrictMode})
}

func (h *HTTP) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: h.CookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: h.secure(), SameSite: http.SameSiteStrictMode})
}

// Routes registers the auth API on mux (all paths under /api/auth/).
func (h *HTTP) Routes(mux *http.ServeMux) {
	pub := func(f http.HandlerFunc) http.Handler { return h.OriginGuard(h.limit(f)) }
	mux.Handle("GET /api/auth/status", h.limit(http.HandlerFunc(h.status)))
	mux.Handle("POST /api/auth/login/begin", pub(h.loginBegin))
	mux.Handle("POST /api/auth/login/finish", pub(h.loginFinish))
	mux.Handle("POST /api/auth/setup/begin", pub(h.setupBegin))
	mux.Handle("POST /api/auth/setup/finish", pub(h.setupFinish))
	mux.Handle("POST /api/auth/enroll/begin", pub(h.enrollBegin))
	mux.Handle("POST /api/auth/enroll/finish", pub(h.enrollFinish))
	authed := func(f http.HandlerFunc) http.Handler { return h.OriginGuard(h.Require(f)) }
	mux.Handle("GET /api/auth/me", authed(h.me))
	mux.Handle("POST /api/auth/logout", authed(h.logout))
	mux.Handle("GET /api/auth/passkeys", authed(h.listPasskeys))
	mux.Handle("DELETE /api/auth/passkeys/{id}", authed(h.deletePasskey))
	mux.Handle("POST /api/auth/enroll-link", authed(h.enrollLink))
}

func (h *HTTP) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.Limiter.Allow(ClientIP(r, h.TrustedHop)) {
			w.Header().Set("Retry-After", "60")
			jsonErr(w, http.StatusTooManyRequests, "too many attempts; try again shortly")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	jsonOut(w, code, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		jsonErr(w, http.StatusBadRequest, "invalid request")
		return false
	}
	return true
}

func (h *HTTP) status(w http.ResponseWriter, r *http.Request) {
	has, err := h.Svc.HasPasskeys(r.Context())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	jsonOut(w, http.StatusOK, map[string]any{"initialized": has, "setup_available": !has && h.Svc.SetupToken != ""})
}

func (h *HTTP) fail(w http.ResponseWriter, r *http.Request, action string, err error) {
	h.Log.Warn("auth failure", "action", action, "err", err, "ip", ClientIP(r, h.TrustedHop))
	switch {
	case errors.Is(err, ErrSetupClosed):
		jsonErr(w, http.StatusForbidden, "setup is not available")
	case errors.Is(err, ErrBadToken):
		jsonErr(w, http.StatusForbidden, "invalid or expired token")
	default:
		jsonErr(w, http.StatusUnauthorized, "authentication failed")
	}
	h.audit(r.Context(), "anonymous", "auth.failed."+action, "")
}

func (h *HTTP) loginBegin(w http.ResponseWriter, r *http.Request) {
	cid, opts, err := h.Svc.BeginLogin(r.Context())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	jsonOut(w, http.StatusOK, map[string]any{"challenge_id": cid, "options": opts})
}

func (h *HTTP) loginFinish(w http.ResponseWriter, r *http.Request) {
	token, pid, err := h.Svc.FinishLogin(r.Context(), r.URL.Query().Get("cid"), r)
	if err != nil {
		h.fail(w, r, "login", err)
		return
	}
	h.setCookie(w, token)
	h.audit(r.Context(), "passkey:"+strconv.FormatInt(pid, 10), "auth.login", "")
	jsonOut(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *HTTP) setupBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	cid, opts, err := h.Svc.BeginSetup(r.Context(), in.Token)
	if err != nil {
		h.fail(w, r, "setup", err)
		return
	}
	jsonOut(w, http.StatusOK, map[string]any{"challenge_id": cid, "options": opts})
}

func (h *HTTP) setupFinish(w http.ResponseWriter, r *http.Request) {
	h.finishRegistration(w, r, "setup")
}

func (h *HTTP) enrollBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	cid, opts, err := h.Svc.BeginEnroll(r.Context(), in.Token)
	if err != nil {
		h.fail(w, r, "enroll", err)
		return
	}
	jsonOut(w, http.StatusOK, map[string]any{"challenge_id": cid, "options": opts})
}

func (h *HTTP) enrollFinish(w http.ResponseWriter, r *http.Request) {
	h.finishRegistration(w, r, "enroll")
}

func (h *HTTP) finishRegistration(w http.ResponseWriter, r *http.Request, kind string) {
	name := r.URL.Query().Get("name")
	pid, err := h.Svc.FinishRegistration(r.Context(), kind, r.URL.Query().Get("cid"), name, r)
	if err != nil {
		h.fail(w, r, kind, err)
		return
	}
	h.audit(r.Context(), "passkey:"+strconv.FormatInt(pid, 10), "auth.passkey_registered."+kind, "")
	// Registration does not create a session: the client must complete a login
	// ceremony with the new passkey.
	jsonOut(w, http.StatusOK, map[string]string{"status": "registered"})
}

func (h *HTTP) me(w http.ResponseWriter, r *http.Request) {
	id, _ := IdentityFrom(r.Context())
	jsonOut(w, http.StatusOK, map[string]any{"passkey_id": id.PasskeyID})
}

func (h *HTTP) logout(w http.ResponseWriter, r *http.Request) {
	id, _ := IdentityFrom(r.Context())
	_ = h.Svc.Logout(r.Context(), id.Token)
	h.clearCookie(w)
	h.audit(r.Context(), "passkey:"+strconv.FormatInt(id.PasskeyID, 10), "auth.logout", "")
	jsonOut(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *HTTP) listPasskeys(w http.ResponseWriter, r *http.Request) {
	ps, err := h.Svc.ListPasskeys(r.Context())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	jsonOut(w, http.StatusOK, ps)
}

func (h *HTTP) deletePasskey(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	who, _ := IdentityFrom(r.Context())
	switch err := h.Svc.DeletePasskey(r.Context(), id); {
	case errors.Is(err, ErrLastPasskey):
		jsonErr(w, http.StatusConflict, "cannot remove the last passkey")
	case err != nil:
		jsonErr(w, http.StatusInternalServerError, "internal error")
	default:
		h.audit(r.Context(), "passkey:"+strconv.FormatInt(who.PasskeyID, 10), "auth.passkey_removed", strconv.FormatInt(id, 10))
		jsonOut(w, http.StatusOK, map[string]string{"status": "removed"})
	}
}

func (h *HTTP) enrollLink(w http.ResponseWriter, r *http.Request) {
	who, _ := IdentityFrom(r.Context())
	token, exp, err := h.Svc.CreateEnrollLink(r.Context(), who.PasskeyID)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.audit(r.Context(), "passkey:"+strconv.FormatInt(who.PasskeyID, 10), "auth.enroll_link_created", "")
	// The token travels in the URL fragment: browsers never send fragments to
	// servers, so it stays out of access logs and Referer headers.
	jsonOut(w, http.StatusOK, map[string]any{"url": strings.TrimRight(h.BaseURL, "/") + "/enroll#" + token, "expires_at": exp.Format(time.RFC3339), "ttl_minutes": int(EnrollLinkTTL.Minutes())})
}
