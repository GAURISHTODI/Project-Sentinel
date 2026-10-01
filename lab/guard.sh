#!/usr/bin/env bash
# Lab-only target guard. Source this at the top of every attack script:
#   source "$(dirname "$0")/guard.sh"
#   require_lab_target "$TARGET"
#
# Aborts (exit 1) unless the target resolves to an address inside the lab network
# (172.30.0.0/24) or is localhost/127.0.0.1. No real-world host is ever permitted.
set -euo pipefail

LAB_CIDR_PREFIX="172.30.0."

require_lab_target() {
  local target="${1:-}"
  if [[ -z "$target" ]]; then
    echo "guard: no target specified; refusing to run" >&2
    exit 1
  fi
  # strip scheme and port/path if a URL was passed
  local host="$target"
  host="${host#http://}"
  host="${host#https://}"
  host="${host%%/*}"
  host="${host%%:*}"

  case "$host" in
    localhost|127.0.0.1)
      return 0
      ;;
    "$LAB_CIDR_PREFIX"*)
      return 0
      ;;
    *)
      # resolve hostnames (e.g. docker service names like target-shop) and check the IP
      local resolved
      resolved="$(getent hosts "$host" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
      if [[ "$resolved" == "$LAB_CIDR_PREFIX"* ]]; then
        return 0
      fi
      echo "guard: target '$target' (resolved: '${resolved:-unresolved}') is not inside the lab network (${LAB_CIDR_PREFIX}0/24) or localhost; refusing to run" >&2
      exit 1
      ;;
  esac
}
