-- B2B API platform (PostgreSQL profile only): organizations, hashed API keys, usage metering.
-- Keys are never stored in clear — only a SHA-256 hash plus a short display prefix.

CREATE TABLE organization (
    id         TEXT PRIMARY KEY,
    name       TEXT        NOT NULL,
    plan       TEXT        NOT NULL DEFAULT 'FREE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE api_key (
    id           TEXT PRIMARY KEY,
    org_id       TEXT        NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
    key_hash     TEXT        NOT NULL UNIQUE,
    key_prefix   TEXT        NOT NULL,
    name         TEXT,
    revoked      BOOLEAN     NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);
CREATE INDEX idx_api_key_org ON api_key (org_id);

CREATE TABLE usage_event (
    id         BIGSERIAL PRIMARY KEY,
    org_id     TEXT        REFERENCES organization (id) ON DELETE SET NULL,
    api_key_id TEXT,
    ip         TEXT,
    endpoint   TEXT        NOT NULL,
    status     INT         NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_usage_org_time ON usage_event (org_id, created_at);
CREATE INDEX idx_usage_ip_time  ON usage_event (ip, created_at);
