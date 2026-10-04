#!/usr/bin/env bash
# Create or update Sentinel's least-privilege PostgreSQL login roles, then apply sql/roles.sql.
# Passwords come from the environment and are sent to psql on stdin, so they never appear in a
# command line, a file or git. Needs the core stack running and the POSTGRES_* variables set.
#
#   export DB_DETECT_PASSWORD=... DB_API_PASSWORD=... DB_READER_PASSWORD=...
#   bash scripts/db_roles.sh
set -euo pipefail
cd "$(dirname "$0")/.."

: "${DB_DETECT_PASSWORD:?set DB_DETECT_PASSWORD}"
: "${DB_API_PASSWORD:?set DB_API_PASSWORD}"
: "${DB_READER_PASSWORD:?set DB_READER_PASSWORD}"
CONTAINER="${POSTGRES_CONTAINER:-sentinel-postgres-1}"
export MSYS_NO_PATHCONV=1

psql_in() {
  docker exec -i "$CONTAINER" psql -U sentinel -d sentinel -v ON_ERROR_STOP=1 "$@"
}

{
  printf "\\set detect_pw '%s'\n" "$DB_DETECT_PASSWORD"
  printf "\\set api_pw '%s'\n" "$DB_API_PASSWORD"
  printf "\\set reader_pw '%s'\n" "$DB_READER_PASSWORD"
  cat <<'SQL'
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_detect') AS need_detect \gset
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_api') AS need_api \gset
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_reader') AS need_reader \gset
\if :need_detect
CREATE ROLE sentinel_detect LOGIN PASSWORD :'detect_pw';
\else
ALTER ROLE sentinel_detect LOGIN PASSWORD :'detect_pw';
\endif
\if :need_api
CREATE ROLE sentinel_api LOGIN PASSWORD :'api_pw';
\else
ALTER ROLE sentinel_api LOGIN PASSWORD :'api_pw';
\endif
\if :need_reader
CREATE ROLE sentinel_reader LOGIN PASSWORD :'reader_pw';
\else
ALTER ROLE sentinel_reader LOGIN PASSWORD :'reader_pw';
\endif
SQL
  cat sql/roles.sql
} | psql_in

echo "[db_roles] sentinel_detect, sentinel_api, sentinel_reader provisioned; grants applied"
