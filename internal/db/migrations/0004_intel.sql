-- Operator-configured threat-intelligence feeds. Nothing is shipped by default.
CREATE TABLE intel_feeds (
    id              BIGSERIAL PRIMARY KEY,
    url             TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL DEFAULT '',
    license         TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    etag            TEXT NOT NULL DEFAULT '',
    content_sha256  TEXT NOT NULL DEFAULT '',
    signature_count INTEGER NOT NULL DEFAULT 0,
    last_fetched_at TIMESTAMPTZ,
    last_ok_at      TIMESTAMPTZ,
    last_status     TEXT NOT NULL DEFAULT 'pending' CHECK (last_status IN ('pending','ok','not_modified','error')),
    last_error      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE intel_signatures (
    feed_id    BIGINT NOT NULL REFERENCES intel_feeds(id) ON DELETE CASCADE,
    sig_id     TEXT NOT NULL,
    family     TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('substring','sha256')),
    value      TEXT NOT NULL,
    severity   TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    provenance TEXT NOT NULL,
    PRIMARY KEY (feed_id, sig_id)
);

-- One row: a hash of the active external signature set. Workers compare it to
-- their cache, so a refresh on one worker reaches the others.
CREATE TABLE intel_state (
    id         SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    hash       TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO intel_state (id, hash) VALUES (1, '');
