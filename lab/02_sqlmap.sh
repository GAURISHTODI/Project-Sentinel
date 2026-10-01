#!/usr/bin/env bash
# sqlmap against the lab target's known-vulnerable search endpoint (v1 only; F-06 in owasp-findings.md).
# Usage: lab/02_sqlmap.sh [target_base_url] (default: target-shop on the lab network)
set -euo pipefail
cd "$(dirname "$0")"
source ./guard.sh
export MSYS_NO_PATHCONV=1  # Windows Git Bash: stop docker volume paths (/out, /wordlists) being rewritten as C: paths

TARGET="${1:-http://172.30.0.11:8080}"
require_lab_target "$TARGET"

OUT_DIR="../results/lab"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%dT%H%M%S)"

echo "[sqlmap] attacking ${TARGET}/api/search?q=test (lab network only)"
docker build -q -t sentinel-lab/sqlmap ./tools/sqlmap >/dev/null

docker run --rm --network lab -v "$(pwd)/../results/lab:/out" sentinel-lab/sqlmap \
  -u "${TARGET}/api/search?q=test" \
  --batch --level=2 --risk=1 \
  --output-dir=/out/sqlmap_${TS}

echo "[sqlmap] results written to results/lab/sqlmap_${TS}/"
