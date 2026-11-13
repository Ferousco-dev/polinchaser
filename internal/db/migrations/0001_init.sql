CREATE TABLE installations (
    id                     BIGSERIAL PRIMARY KEY,
    github_installation_id BIGINT NOT NULL UNIQUE,
    account_id             BIGINT NOT NULL,
    account_login          TEXT NOT NULL,
    account_type           TEXT NOT NULL CHECK (account_type IN ('User','Organization')),
    repository_selection   TEXT NOT NULL DEFAULT 'selected' CHECK (repository_selection IN ('all','selected')),
    suspended              BOOLEAN NOT NULL DEFAULT FALSE,
    removed_at             TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE repositories (
    id              BIGSERIAL PRIMARY KEY,
    installation_id BIGINT NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
    github_repo_id  BIGINT NOT NULL,
    full_name       TEXT NOT NULL,
    default_branch  TEXT NOT NULL DEFAULT 'main',
    private         BOOLEAN NOT NULL DEFAULT FALSE,
    archived        BOOLEAN NOT NULL DEFAULT FALSE,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (installation_id, github_repo_id)
);
CREATE INDEX repositories_installation_idx ON repositories (installation_id) WHERE active;

CREATE TABLE webhook_deliveries (
    delivery_id  TEXT PRIMARY KEY,
    event        TEXT NOT NULL,
    action       TEXT NOT NULL DEFAULT '',
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE jobs (
    id               BIGSERIAL PRIMARY KEY,
    kind             TEXT NOT NULL,
    payload          JSONB NOT NULL DEFAULT '{}',
    dedupe_key       TEXT UNIQUE,
    state            TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','succeeded','dead')),
    attempts         INT NOT NULL DEFAULT 0,
    max_attempts     INT NOT NULL DEFAULT 5,
    run_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_by        TEXT,
    lease_expires_at TIMESTAMPTZ,
    last_error       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at      TIMESTAMPTZ
);
CREATE INDEX jobs_claim_idx ON jobs (run_at) WHERE state = 'queued';
CREATE INDEX jobs_lease_idx ON jobs (lease_expires_at) WHERE state = 'running';

CREATE TABLE scans (
    id              BIGSERIAL PRIMARY KEY,
    installation_id BIGINT NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
    repository_id   BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    trigger         TEXT NOT NULL CHECK (trigger IN ('install','push','pull_request','scheduled','manual')),
    commit_sha      TEXT NOT NULL,
    base_sha        TEXT,
    branch          TEXT,
    pr_number       INT,
    status          TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','clean','findings_detected','incomplete','failed','timed_out')),
    rule_version    TEXT,
    files_scanned   INT NOT NULL DEFAULT 0,
    error           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ
);
CREATE INDEX scans_repo_idx ON scans (repository_id, created_at DESC);

CREATE TABLE findings (
    id                BIGSERIAL PRIMARY KEY,
    installation_id   BIGINT NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
    repository_id     BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint       TEXT NOT NULL,
    rule_id           TEXT NOT NULL,
    rule_version      TEXT NOT NULL,
    category          TEXT NOT NULL,
    severity          TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    confidence        TEXT NOT NULL CHECK (confidence IN ('confirmed_signature','high','medium','low')),
    path              TEXT NOT NULL,
    title             TEXT NOT NULL,
    explanation       TEXT NOT NULL,
    remediation       TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved','false_positive','accepted_risk')),
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_detected_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repository_id, fingerprint)
);
CREATE INDEX findings_open_idx ON findings (installation_id, severity) WHERE status = 'open';

CREATE TABLE finding_occurrences (
    id          BIGSERIAL PRIMARY KEY,
    finding_id  BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_id     BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    commit_sha  TEXT NOT NULL,
    line_start  INT,
    line_end    INT,
    evidence    TEXT NOT NULL,
    UNIQUE (finding_id, scan_id)
);

CREATE TABLE audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    installation_id BIGINT REFERENCES installations(id) ON DELETE SET NULL,
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    target          TEXT NOT NULL DEFAULT '',
    detail          JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_idx ON audit_logs (installation_id, created_at DESC);
