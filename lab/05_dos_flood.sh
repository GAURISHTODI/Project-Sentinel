#!/usr/bin/env bash
# Scripted, bounded HTTP flood against our own lab target (textbook test only: single source,
# fixed total request count, no amplification, no spoofing). Demonstrates SEN-007 (HTTP flood)
# and the responder gateway's rate limiter (F-02 class of finding) on real traffic.
# Usage: lab/05_dos_flood.sh [target_base_url] [total_requests] [concurrency]
set -euo pipefail
cd "$(dirname "$0")"
source ./guard.sh
export MSYS_NO_PATHCONV=1  # Windows Git Bash: stop docker volume paths (/out, /wordlists) being rewritten as C: paths

TARGET="${1:-http://172.30.0.10:8080}"   # default: through the responder gateway, not direct to the shop
TOTAL="${2:-400}"
CONCURRENCY="${3:-20}"
require_lab_target "$TARGET"

OUT_DIR="../results/lab"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%dT%H%M%S)"
LOG="${OUT_DIR}/dos_${TS}.txt"

echo "[dos] sending ${TOTAL} requests (concurrency ${CONCURRENCY}) to ${TARGET} (lab network only)" | tee "$LOG"

docker run --rm --network lab curlimages/curl:8.10.1 sh -c "
  seq 1 ${TOTAL} | xargs -P ${CONCURRENCY} -I {} curl -s -o /dev/null -w '%{http_code}\n' '${TARGET}/'
" | sort | uniq -c | tee -a "$LOG"

echo "[dos] status code histogram written to $LOG"
