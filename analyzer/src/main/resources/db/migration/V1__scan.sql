-- Durable store for analyzed reports (PostgreSQL profile only).
-- The full ScanResult is kept as JSONB; the leading columns are projected out for
-- indexing (lookup/dedup by hash) and retention (purge by age).
CREATE TABLE scan (
    id            TEXT PRIMARY KEY,
    sha256        TEXT        NOT NULL,
    file_name     TEXT        NOT NULL,
    artifact_type TEXT,
    score         INT         NOT NULL,
    verdict       TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    report        JSONB       NOT NULL
);

CREATE INDEX idx_scan_sha256     ON scan (sha256);
CREATE INDEX idx_scan_created_at ON scan (created_at);
