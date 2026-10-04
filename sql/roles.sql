-- Least-privilege grants for Sentinel's services. Idempotent; run by scripts/db_roles.sh, which
-- creates the three login roles and sets their passwords from the environment (never from git).
--
--   sentinel_detect  detection + response: writes incidents, lock rows and the audit chain
--   sentinel_api     the FastAPI service: reads everything, updates incident status, manages users
--   sentinel_reader  read-only consumers: Splunk forwarder, triage agent, dashboards

GRANT CONNECT ON DATABASE sentinel TO sentinel_detect, sentinel_api, sentinel_reader;
GRANT USAGE ON SCHEMA public TO sentinel_detect, sentinel_api, sentinel_reader;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sentinel_detect, sentinel_api, sentinel_reader;

GRANT SELECT ON incidents, audit_log, locked_accounts, users, roles TO sentinel_reader;

GRANT SELECT, INSERT, UPDATE ON incidents TO sentinel_detect;
GRANT SELECT, INSERT, UPDATE, DELETE ON locked_accounts TO sentinel_detect;
GRANT SELECT, INSERT ON audit_log TO sentinel_detect;
GRANT USAGE, SELECT ON SEQUENCE incidents_id_seq, audit_log_id_seq TO sentinel_detect;

GRANT SELECT ON incidents, audit_log, locked_accounts, roles TO sentinel_api;
GRANT SELECT, INSERT ON users TO sentinel_api;
GRANT UPDATE (status) ON incidents TO sentinel_api;
GRANT INSERT ON audit_log TO sentinel_api;
GRANT DELETE ON locked_accounts TO sentinel_api;
GRANT USAGE, SELECT ON SEQUENCE users_id_seq, audit_log_id_seq TO sentinel_api;

-- The API audits its own actions (analyst overrides, user changes) into the same chain.
-- The audit chain is append-only. The trigger stops casual edits by any role; the hash chain
-- (verify_chain) is what detects an edit made by someone who can disable the trigger.
CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END
$$;

DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
