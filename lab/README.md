# Sentinel attack lab (T9)

All scripts here run **only** against the isolated `lab` Docker network (`172.30.0.0/24`, `internal: true`
— no internet egress, no host route) or `localhost`. Every script sources `guard.sh` and calls
`require_lab_target` before doing anything, and hard-aborts (`exit 1`) if the target does not resolve
inside that range. No malware, no real-world exploit chains — only textbook tools (Nmap, sqlmap, Hydra,
ZAP) and a bounded, single-source scripted flood, run against our own `target-shop` v1.

`guard.sh` is independently tested in `test_guard.sh` (9 cases: lab IPs, localhost, real external
hosts/IPs, and a deliberately similar-but-wrong subnet `172.30.1.x`, all correctly allowed/refused).

## Scripts
| Script | Tool | Target | What it proves |
|---|---|---|---|
| `01_nmap_scan.sh` | Nmap (`instrumentisto/nmap`) | target-shop direct | Service/version detection; SEN-005 fires on NSE's real HTTP probe user-agent |
| `02_sqlmap.sh` | sqlmap (built image) | `/api/search?q=` | Confirms H2 SQL injection (boolean-blind, error-based, UNION); SEN-002/003/009 fire on its real payload traffic |
| `03_hydra.sh` | Hydra (built image) | `/api/login` | Brute-forces all 4 seed credentials with no lockout (F-02/F-03); SEN-001 fires live |
| `04_zap_baseline.sh` | OWASP ZAP baseline | target-shop | Passive + light active scan, HTML/JSON report |
| `05_dos_flood.sh` | curl (bounded, single-source) | gateway or shop direct | Demonstrates the responder gateway's 300 req/min limit (429 past it) and Sentinel's SEN-007 flood rule |

## Known, honestly-documented limitations
- **Nmap's full port scan does not trigger SEN-004.** target-shop exposes exactly one TCP port; a port
  scan against closed ports never reaches any layer Sentinel can observe (that needs real network/pcap
  capture, built in T12). Only Nmap's HTTP-layer NSE probes are visible, and those correctly trip SEN-005.
- **Hydra requires the `1=` module option** (`/api/login:...:1=:F=error`) because target-shop returns a
  real HTTP 401 for bad credentials, which Hydra's http-post-form module otherwise misreads as a Basic
  Auth challenge and refuses to process as form failures.
- **Sources accumulate suspicion.** Once an attack container's IP is blocklisted by any rule, it stays
  blocked at the gateway (403) for later, unrelated attack runs from the same IP — this is correct, not a
  bug, but it means each new attack technique should be tested either from a fresh IP or after clearing
  `sen:blocklist:<ip>` in Redis if a clean, isolated demonstration of a *different* detector is wanted.
- **The lab network has no internet egress once a tool container joins it** (`internal: true`); images
  must be pulled/built before the container runs with `--network lab`.

## Running a scenario end-to-end
```bash
docker compose --profile core up -d
python -m sentinel.ingest.normalize --group norm-demo &
python -m sentinel.detect.run --group det-demo &
bash lab/02_sqlmap.sh   # or any other script
# check results/metrics.json or query the incidents table directly
```
