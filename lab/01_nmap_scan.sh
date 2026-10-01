#!/usr/bin/env bash
# Nmap port scan + service/version detection against the lab target.
# Usage: lab/01_nmap_scan.sh [target_ip] (default: target-shop container on the lab network)
set -euo pipefail
cd "$(dirname "$0")"
source ./guard.sh
export MSYS_NO_PATHCONV=1  # Windows Git Bash: stop docker volume paths (/out, /wordlists) being rewritten as C: paths

TARGET="${1:-172.30.0.11}"
require_lab_target "$TARGET"

OUT_DIR="../results/lab"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%dT%H%M%S)"

echo "[nmap] scanning $TARGET (lab network only)"
MSYS_NO_PATHCONV=1 docker run --rm --network lab -v "$(pwd)/../results/lab:/out" instrumentisto/nmap:latest \
  -sV -sC -p- --min-rate 500 -T4 -oN "/out/nmap_${TS}.txt" -oX "/out/nmap_${TS}.xml" "$TARGET"

echo "[nmap] results written to results/lab/nmap_${TS}.txt"
