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
CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents (src_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
-- one incident per (event, detector): makes create_incident idempotent
CREATE UNIQUE INDEX IF NOT EXISTS uq_incident_event_detector
    ON incidents (event_id, COALESCE(rule_id, model_name));

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
