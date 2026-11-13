-- Passkey-only operator authentication. There are no passwords and no accounts.
CREATE TABLE admin_identity (
    id          SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    user_handle BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE passkeys (
    id            BIGSERIAL PRIMARY KEY,
    credential_id BYTEA NOT NULL UNIQUE,
    credential    JSONB NOT NULL,
    name          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);

-- Only a SHA-256 of the session token is stored.
CREATE TABLE sessions (
    token_hash   BYTEA PRIMARY KEY,
    passkey_id   BIGINT NOT NULL REFERENCES passkeys(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_expiry_idx ON sessions (expires_at);

-- One-time, short-lived links for adding another device. Only a hash is stored.
CREATE TABLE enrollment_tokens (
    token_hash BYTEA PRIMARY KEY,
    created_by BIGINT REFERENCES passkeys(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ
);

CREATE TABLE auth_challenges (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('login','setup','enroll')),
    data       JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
