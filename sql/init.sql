-- Sentinel schema. Least-privilege roles are added in T21.
CREATE TABLE IF NOT EXISTS roles (
    name TEXT PRIMARY KEY CHECK (name IN ('analyst', 'admin'))
);
INSERT INTO roles (name) VALUES ('analyst'), ('admin') ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL REFERENCES roles (name),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS incidents (
    id            BIGSERIAL PRIMARY KEY,
    event_id      TEXT NOT NULL,
    rule_id       TEXT,
    model_name    TEXT,
    attack_id     TEXT,
    severity      TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    score         DOUBLE PRECISION NOT NULL,
    src_ip        INET,
    username      TEXT,
    explanation   TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'triaged', 'closed')),
    detected_at   TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (rule_id IS NOT NULL OR model_name IS NOT NULL)
);
-- alert grouping: one OPEN incident per (detector, entity, hour); repeats bump event_count
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS dedupe_key  TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS event_count INTEGER NOT NULL DEFAULT 1;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS last_seen   TIMESTAMPTZ;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS first_event_ts DOUBLE PRECISION;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS responded_ts   DOUBLE PRECISION;
CREATE UNIQUE INDEX IF NOT EXISTS uq_incident_open_key
    ON incidents (dedupe_key) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents (src_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
DROP INDEX IF EXISTS uq_incident_event_detector;

CREATE TABLE IF NOT EXISTS locked_accounts (
    username   TEXT PRIMARY KEY,
    reason     TEXT NOT NULL,
    locked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_until TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT,
    detail     JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash  TEXT,
    row_hash   TEXT
);
