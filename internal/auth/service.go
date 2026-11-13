// Package auth implements passkey-only (WebAuthn) operator authentication,
// server-side sessions and one-time device-enrollment links. There are no
// passwords, usernames or sign-up forms.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	SessionTTL    = 12 * time.Hour
	SessionIdle   = 2 * time.Hour
	ChallengeTTL  = 5 * time.Minute
	EnrollLinkTTL = 10 * time.Minute
)

var (
	ErrUnauthenticated = errors.New("auth: unauthenticated")
	ErrSetupClosed     = errors.New("auth: setup is not available")
	ErrBadToken        = errors.New("auth: invalid or expired token")
	ErrLastPasskey     = errors.New("auth: cannot remove the last passkey")
)

type Service struct {
	Pool       *pgxpool.Pool
	WA         *webauthn.WebAuthn
	SetupToken string // from ADMIN_SETUP_TOKEN; empty disables first-time setup
	Now        func() time.Time
}

// New derives the WebAuthn relying party from the public base URL.
func New(pool *pgxpool.Pool, baseURL, setupToken string) (*Service, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("auth: BASE_URL is required for passkeys")
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID: u.Hostname(), RPDisplayName: "PolinChaser", RPOrigins: []string{u.Scheme + "://" + u.Host},
	})
	if err != nil {
		return nil, err
	}
	return &Service{Pool: pool, WA: wa, SetupToken: setupToken, Now: time.Now}, nil
}

type operator struct {
	handle []byte
	creds  []webauthn.Credential
}

func (o operator) WebAuthnID() []byte                         { return o.handle }
func (o operator) WebAuthnName() string                       { return "operator" }
func (o operator) WebAuthnDisplayName() string                { return "PolinChaser operator" }
func (o operator) WebAuthnCredentials() []webauthn.Credential { return o.creds }

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) []byte { h := sha256.Sum256([]byte(t)); return h[:] }

func (s *Service) load(ctx context.Context) (operator, error) {
	var o operator
	err := s.Pool.QueryRow(ctx, `SELECT user_handle FROM admin_identity WHERE id=1`).Scan(&o.handle)
	if errors.Is(err, pgx.ErrNoRows) {
		h := make([]byte, 32)
		_, _ = rand.Read(h)
		if _, err := s.Pool.Exec(ctx, `INSERT INTO admin_identity(id,user_handle) VALUES (1,$1) ON CONFLICT DO NOTHING`, h); err != nil {
			return o, err
		}
		err = s.Pool.QueryRow(ctx, `SELECT user_handle FROM admin_identity WHERE id=1`).Scan(&o.handle)
	}
	if err != nil {
		return o, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT credential FROM passkeys ORDER BY id`)
	if err != nil {
		return o, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var c webauthn.Credential
		if err := rows.Scan(&raw); err != nil {
			return o, err
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return o, err
		}
		o.creds = append(o.creds, c)
	}
	return o, rows.Err()
}

func (s *Service) HasPasskeys(ctx context.Context) (bool, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM passkeys`).Scan(&n)
	return n > 0, err
}

type challenge struct {
	Session   webauthn.SessionData `json:"session"`
	TokenHash []byte               `json:"token_hash,omitempty"`
}

func (s *Service) saveChallenge(ctx context.Context, kind string, c challenge) (string, error) {
	id := randToken(18)
	b, _ := json.Marshal(c)
	_, err := s.Pool.Exec(ctx, `INSERT INTO auth_challenges(id,kind,data,expires_at) VALUES ($1,$2,$3,$4)`, id, kind, b, s.Now().Add(ChallengeTTL))
	return id, err
}

// takeChallenge is single-use: it deletes the row as it reads it.
func (s *Service) takeChallenge(ctx context.Context, kind, id string) (challenge, error) {
	var raw []byte
	err := s.Pool.QueryRow(ctx, `DELETE FROM auth_challenges WHERE id=$1 AND kind=$2 AND expires_at > $3 RETURNING data`, id, kind, s.Now()).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return challenge{}, ErrBadToken
	}
	var c challenge
	if err == nil {
		err = json.Unmarshal(raw, &c)
	}
	return c, err
}

var regOpts = []webauthn.RegistrationOption{
	webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
		RequireResidentKey: protocol.ResidentKeyRequired(),
		ResidentKey:        protocol.ResidentKeyRequirementRequired,
		UserVerification:   protocol.VerificationRequired,
	}),
	webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
}

func (s *Service) beginRegistration(ctx context.Context, kind string, tokenHash []byte) (string, *protocol.CredentialCreation, error) {
	o, err := s.load(ctx)
	if err != nil {
		return "", nil, err
	}
	opts := append([]webauthn.RegistrationOption{}, regOpts...)
	var ex []protocol.CredentialDescriptor
	for _, c := range o.creds {
		ex = append(ex, c.Descriptor())
	}
	opts = append(opts, webauthn.WithExclusions(ex))
	creation, session, err := s.WA.BeginRegistration(o, opts...)
	if err != nil {
		return "", nil, err
	}
	id, err := s.saveChallenge(ctx, kind, challenge{Session: *session, TokenHash: tokenHash})
	return id, creation, err
}

// BeginSetup starts first-time enrollment. It requires the operator's
// ADMIN_SETUP_TOKEN and is closed as soon as any passkey exists.
func (s *Service) BeginSetup(ctx context.Context, token string) (string, *protocol.CredentialCreation, error) {
	has, err := s.HasPasskeys(ctx)
	if err != nil {
		return "", nil, err
	}
	if has || s.SetupToken == "" {
		return "", nil, ErrSetupClosed
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.SetupToken)) != 1 {
		return "", nil, ErrBadToken
	}
	return s.beginRegistration(ctx, "setup", nil)
}

// BeginEnroll validates a one-time enrollment token without consuming it.
func (s *Service) BeginEnroll(ctx context.Context, token string) (string, *protocol.CredentialCreation, error) {
	h := hashToken(token)
	var ok bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM enrollment_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at > $2)`, h, s.Now()).Scan(&ok); err != nil {
		return "", nil, err
	}
	if !ok {
		return "", nil, ErrBadToken
	}
	return s.beginRegistration(ctx, "enroll", h)
}

// FinishRegistration verifies the attestation and stores the passkey.
// For enrollment it consumes the token in the same transaction, so a link can
// register at most one passkey even under concurrent attempts.
func (s *Service) FinishRegistration(ctx context.Context, kind, cid, name string, req webauthnRequest) (int64, error) {
	ch, err := s.takeChallenge(ctx, kind, cid)
	if err != nil {
		return 0, err
	}
	o, err := s.load(ctx)
	if err != nil {
		return 0, err
	}
	cred, err := s.WA.FinishRegistration(o, ch.Session, req)
	if err != nil {
		return 0, fmt.Errorf("auth: registration rejected: %w", err)
	}
	raw, _ := json.Marshal(cred)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	switch kind {
	case "setup":
		if _, err := tx.Exec(ctx, `LOCK TABLE passkeys IN EXCLUSIVE MODE`); err != nil {
			return 0, err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM passkeys`).Scan(&n); err != nil {
			return 0, err
		}
		if n > 0 {
			return 0, ErrSetupClosed
		}
	case "enroll":
		tag, err := tx.Exec(ctx, `UPDATE enrollment_tokens SET used_at=$2 WHERE token_hash=$1 AND used_at IS NULL AND expires_at > $2`, ch.TokenHash, s.Now())
		if err != nil {
			return 0, err
		}
		if tag.RowsAffected() != 1 {
			return 0, ErrBadToken
		}
	}
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 60 {
		name = name[:60]
	}
	var id int64
	if err := tx.QueryRow(ctx, `INSERT INTO passkeys(credential_id, credential, name) VALUES ($1,$2,$3) RETURNING id`, cred.ID, raw, name).Scan(&id); err != nil {
		return 0, err
	}
	return id, tx.Commit(ctx)
}

func (s *Service) BeginLogin(ctx context.Context) (string, *protocol.CredentialAssertion, error) {
	assertion, session, err := s.WA.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return "", nil, err
	}
	id, err := s.saveChallenge(ctx, "login", challenge{Session: *session})
	return id, assertion, err
}

// FinishLogin verifies the assertion, rejects cloned authenticators, and
// returns a new session token (shown once; only its hash is stored).
func (s *Service) FinishLogin(ctx context.Context, cid string, req webauthnRequest) (token string, passkeyID int64, err error) {
	ch, err := s.takeChallenge(ctx, "login", cid)
	if err != nil {
		return "", 0, err
	}
	o, err := s.load(ctx)
	if err != nil {
		return "", 0, err
	}
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		if subtle.ConstantTimeCompare(userHandle, o.handle) != 1 {
			return nil, errors.New("unknown user handle")
		}
		return o, nil
	}
	cred, err := s.WA.FinishDiscoverableLogin(handler, ch.Session, req)
	if err != nil {
		return "", 0, fmt.Errorf("auth: login rejected: %w", err)
	}
	if cred.Authenticator.CloneWarning {
		return "", 0, errors.New("auth: authenticator signature counter regressed (possible clone)")
	}
	raw, _ := json.Marshal(cred)
	if err := s.Pool.QueryRow(ctx, `UPDATE passkeys SET credential=$2, last_used_at=$3 WHERE credential_id=$1 RETURNING id`, cred.ID, raw, s.Now()).Scan(&passkeyID); err != nil {
		return "", 0, err
	}
	token = randToken(32)
	now := s.Now()
	_, err = s.Pool.Exec(ctx, `INSERT INTO sessions(token_hash, passkey_id, created_at, last_seen_at, expires_at) VALUES ($1,$2,$3,$3,$4)`,
		hashToken(token), passkeyID, now, now.Add(SessionTTL))
	_, _ = s.Pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1`, now)
	_, _ = s.Pool.Exec(ctx, `DELETE FROM auth_challenges WHERE expires_at < $1`, now)
	return token, passkeyID, err
}

// Session validates a token, enforcing absolute and idle expiry.
func (s *Service) Session(ctx context.Context, token string) (passkeyID int64, err error) {
	if token == "" {
		return 0, ErrUnauthenticated
	}
	now := s.Now()
	err = s.Pool.QueryRow(ctx, `UPDATE sessions SET last_seen_at=$2
		WHERE token_hash=$1 AND expires_at > $2 AND last_seen_at > $3 RETURNING passkey_id`,
		hashToken(token), now, now.Add(-SessionIdle)).Scan(&passkeyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrUnauthenticated
	}
	return passkeyID, err
}

func (s *Service) Logout(ctx context.Context, token string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, hashToken(token))
	return err
}

// CreateEnrollLink mints a one-time token valid for EnrollLinkTTL.
func (s *Service) CreateEnrollLink(ctx context.Context, byPasskey int64) (token string, expires time.Time, err error) {
	token = randToken(32)
	expires = s.Now().Add(EnrollLinkTTL)
	_, err = s.Pool.Exec(ctx, `INSERT INTO enrollment_tokens(token_hash, created_by, expires_at) VALUES ($1,$2,$3)`, hashToken(token), byPasskey, expires)
	return
}

type PasskeyInfo struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

func (s *Service) ListPasskeys(ctx context.Context) ([]PasskeyInfo, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, name, created_at, last_used_at FROM passkeys ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PasskeyInfo{}
	for rows.Next() {
		var p PasskeyInfo
		if err := rows.Scan(&p.ID, &p.Name, &p.CreatedAt, &p.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePasskey removes a passkey (and, by cascade, its sessions). The last
// passkey cannot be removed, so the operator cannot lock themselves out.
func (s *Service) DeletePasskey(ctx context.Context, id int64) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `LOCK TABLE passkeys IN EXCLUSIVE MODE`); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM passkeys`).Scan(&n); err != nil {
		return err
	}
	if n <= 1 {
		return ErrLastPasskey
	}
	if _, err := tx.Exec(ctx, `DELETE FROM passkeys WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
