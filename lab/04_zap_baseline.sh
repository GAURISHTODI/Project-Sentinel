#!/usr/bin/env bash
# OWASP ZAP baseline scan (passive + light active checks) against the lab target.
# Usage: lab/04_zap_baseline.sh [target_base_url] (default: target-shop on the lab network)
set -euo pipefail
cd "$(dirname "$0")"
source ./guard.sh
export MSYS_NO_PATHCONV=1  # Windows Git Bash: stop docker volume paths (/out, /wordlists) being rewritten as C: paths

command -v docker >/dev/null || { echo "[zap] docker is not on PATH; nothing was scanned" >&2; exit 1; }

# ZAP exits 0 (pass), 1 (failures found) or 2 (warnings found). Any other code is a real error.
zap_exit_ok() {
  case "$1" in
    0|1|2) return 0 ;;
    *) echo "[zap] scanner failed with exit $1" >&2; exit "$1" ;;
  esac
}

TARGET="${1:-http://172.30.0.11:8080}"
require_lab_target "$TARGET"

OUT_DIR="../results/lab"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%dT%H%M%S)"

echo "[zap] baseline (passive) scan of ${TARGET} (lab network only)"
docker run --rm --network lab -v "$(pwd)/../results/lab:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t "$TARGET" \
  -r "zap_baseline_${TS}.html" \
  -J "zap_baseline_${TS}.json" \
  -I && zap_exit_ok 0 || zap_exit_ok $?

echo "[zap] baseline results written to results/lab/zap_baseline_${TS}.html"

echo "[zap] full (active) scan of ${TARGET} (lab network only) -- this sends real attack payloads"
docker run --rm --network lab -v "$(pwd)/../results/lab:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
  -t "$TARGET" \
  -r "zap_full_${TS}.html" \
  -J "zap_full_${TS}.json" \
  -I && zap_exit_ok 0 || zap_exit_ok $?

echo "[zap] active-scan results written to results/lab/zap_full_${TS}.html"
