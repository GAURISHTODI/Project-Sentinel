#!/usr/bin/env bash
GUARD="$(dirname "$0")/guard.sh"

run_case() {
  local desc="$1"; local target="$2"; local expect="$3"
  local out rc
  out=$(bash -c "source '$GUARD'; require_lab_target '$target'" 2>&1)
  rc=$?
  if [[ "$expect" == "pass" && $rc -eq 0 ]]; then
    echo "PASS: $desc"
  elif [[ "$expect" == "fail" && $rc -ne 0 ]]; then
    echo "PASS: $desc (correctly aborted: $out)"
  else
    echo "FAIL: $desc (rc=$rc out=$out)"
  fi
}

run_case "lab IP" "172.30.0.11:8080" pass
run_case "localhost" "127.0.0.1:8080" pass
run_case "localhost no port" "localhost" pass
run_case "real external host google.com" "google.com" fail
run_case "real external IP 8.8.8.8" "8.8.8.8" fail
run_case "empty target" "" fail
run_case "https scheme lab target" "https://172.30.0.11:8080/path" pass
run_case "private but non-lab IP 192.168.1.1" "192.168.1.1" fail
run_case "lab-looking but wrong subnet 172.30.1.11" "172.30.1.11" fail
