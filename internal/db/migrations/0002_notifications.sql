ALTER TABLE scans ADD COLUMN author TEXT;
ALTER TABLE findings ADD COLUMN notified_at TIMESTAMPTZ;

CREATE TABLE notification_settings (
    installation_id BIGINT PRIMARY KEY REFERENCES installations(id) ON DELETE CASCADE,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    recipients      TEXT[] NOT NULL DEFAULT '{}',
    min_severity    TEXT NOT NULL DEFAULT 'high' CHECK (min_severity IN ('critical','high','medium','low','info')),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE notifications (
    id              BIGSERIAL PRIMARY KEY,
    installation_id BIGINT NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
    scan_id         BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, kind)
);

CREATE TABLE notification_deliveries (
    id              BIGSERIAL PRIMARY KEY,
    notification_id BIGINT NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    recipient       TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed')),
    provider_id     TEXT,
    attempts        INT NOT NULL DEFAULT 0,
    last_error      TEXT,
    sent_at         TIMESTAMPTZ,
    UNIQUE (notification_id, recipient)
);
