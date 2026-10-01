#!/usr/bin/env bash
# OWASP ZAP baseline scan (passive + light active checks) against the lab target.
# Usage: lab/04_zap_baseline.sh [target_base_url] (default: target-shop on the lab network)
set -euo pipefail
cd "$(dirname "$0")"
source ./guard.sh
export MSYS_NO_PATHCONV=1  # Windows Git Bash: stop docker volume paths (/out, /wordlists) being rewritten as C: paths

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
  -I || true   # zap-baseline.py exits non-zero when it finds warnings; that is expected, not a script failure

echo "[zap] baseline results written to results/lab/zap_baseline_${TS}.html"

echo "[zap] full (active) scan of ${TARGET} (lab network only) -- this sends real attack payloads"
docker run --rm --network lab -v "$(pwd)/../results/lab:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
  -t "$TARGET" \
  -r "zap_full_${TS}.html" \
  -J "zap_full_${TS}.json" \
  -I || true   # also exits non-zero on findings; expected

echo "[zap] active-scan results written to results/lab/zap_full_${TS}.html"
