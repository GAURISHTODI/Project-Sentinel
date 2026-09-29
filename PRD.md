# PRD — Sentinel: AI-Driven Threat Detection & Automated Response Platform (Full Scope)

| | |
|---|---|
| Owner | Gaurish Todi |
| Status | Final scope v2 (complete platform, all phases required) |
| Purpose | Flagship portfolio project for the Walmart Global Tech cybersecurity internship (2027 batch) |
| Companion | Agent SecOps (pre-deployment IaC gating). Sentinel is runtime detection and response; Sentinel's own Terraform/K8s is scanned by Agent SecOps. |

## 1. Problem
Large e-commerce platforms face credential stuffing, account takeover, injection, scanning, bot/DoS traffic, phishing and payment fraud
at scale. Security teams need fast detection across heterogeneous logs, low false positives, and automated first response.
Rule-only systems miss novel behavior; ML-only systems are opaque and unsafe to act on alone. Sentinel combines both, closes the loop
with automated response, gives analysts visibility, adds an LLM triage assistant hardened against prompt injection, and is itself
built and shipped securely.

## 2. Goals
- G1 Multi-source ingestion (app, auth, network, Windows endpoint) into one normalized schema over Kafka.
- G2 Rule detection mapped to MITRE ATT&CK.
- G3 ML detection: supervised network intrusion, unsupervised anomaly, phishing URL, fraud.
- G4 Automated response (SOAR-lite): block, lock, rate-limit, notify, incident record, with audit trail.
- G5 Real attack lab against our own vulnerable target, with OWASP Top 10 findings and verified detections.
- G6 Visibility: Splunk (HEC), Prometheus/Grafana, pcap validation with Wireshark/tshark.
- G7 LLM alert-triage agent with prompt-injection defenses and tests.
- G8 DevSecOps pipeline and platform security (SAST, SCA, secrets, container, IaC, DAST; JWT/RBAC; secrets management).
- G9 Reproducible, measured metrics written to `results/metrics.json`.
- G10 One-command local run; Kubernetes (kind) + Terraform deployment path.

## 3. Non-goals
Multi-tenant production SIEM, horizontal-scale claims, attacks outside the lab, novel deep-learning research.

## 4. Users
SOC analyst (incidents, blocklist, triage), security engineer (rules, models), reviewer/interviewer (clone, run, read metrics).

## 5. JD alignment
| JD requirement | Sentinel feature |
|---|---|
| Identify, analyze, mitigate threats | Rules + ML + automated response |
| Vulnerability assessment and pen testing | Attack lab (Nmap, sqlmap, Hydra, ZAP, Burp), OWASP findings report, v1 vulnerable -> v2 fixed |
| Incident response, threat hunting, SOC | Incidents API, audit log, triage agent, Splunk searches/dashboards, runbook |
| Design and develop security solutions | Full platform incl. gateway enforcement |
| Automation scripts and tools for monitoring | Generator, lab scripts, evaluation harness, notifiers |
| AI/ML: anomaly, phishing, malware analysis, fraud | RF/XGBoost intrusion, Isolation Forest + autoencoder, phishing URL model, fraud model, malware-aware endpoint features |
| Research/document trends (zero-days, AI in security) | `docs/writeup.md` + threat-model.md |
| Networking (TCP/IP, firewalls, VPN, IDS/IPS) | Flow features, Zeek/Suricata, port-scan/DoS detection, gateway rate limiting, pcap validation |
| Crypto, authn, access control | JWT + RBAC on API/gateway, password hashing in target v2, TLS between services, secrets in Vault |
| Linux/Windows system security | Linux containers/hardening; Windows endpoint logs via WinPulse/Sysmon-style exporter |
| Wireshark, Burp Suite, Nmap, Splunk | All four used and documented |
| OWASP Top 10 | SQLi, XSS, broken auth, security misconfig, etc. in target; detections and fixes |

## 6. Functional requirements

### 6.1 Ingestion
- FR-1 Generator emits benign + labeled attack traffic for sources `app`, `auth`, `network`, `endpoint`.
- FR-2 Per-source normalizers (app/nginx JSON, auth, Zeek `conn.log`/Suricata `eve.json`, Windows Sysmon-style events from WinPulse) publish to `events.normalized`.
- FR-3 Every event carries `timestamp_generated`; configurable `--eps`, `--duration`, `--attack-mix`.
- FR-4 Real logs from the target app and lab attacks flow through the same pipeline (not only synthetic).

### 6.2 Rule detection (12+ rules, 8+ ATT&CK techniques)
SEN-001 brute force (T1110) · SEN-002 SQLi (T1190) · SEN-003 XSS (T1190) · SEN-004 port scan (T1046) · SEN-005 scanner user-agent (T1595) ·
SEN-006 valid account abuse, new geo/IP (T1078) · SEN-007 HTTP flood (T1499) · SEN-008 credential stuffing (T1110.004) ·
SEN-009 path traversal (T1190) · SEN-010 suspicious process spawn on endpoint (T1059) · SEN-011 encoded PowerShell (T1059.001) · SEN-012 new service/persistence (T1543).
- FR-5 Sigma-style YAML, Redis sliding windows for thresholds, hot reload.

### 6.3 ML detection
- FR-6 Supervised network IDS: Random Forest and XGBoost on CIC-IDS2017 (stratified 200k sample default, seed 42, split before scaling); optional multi-class attack-type model; report per-class metrics.
- FR-7 Unsupervised anomaly: Isolation Forest + PyTorch autoencoder trained on benign; reported separately.
- FR-8 Phishing URL classifier (lexical features; public dataset).
- FR-9 Fraud model (Kaggle credit-card fraud dataset, CPU-friendly) on transaction events, with imbalance handling and PR-AUC reporting.
- FR-10 MLflow tracking; `model_card.json` per model; predictor service with thresholds configurable.
- FR-11 Endpoint anomaly features (process/command-line entropy) for malware-behavior flagging.

### 6.4 Response (SOAR-lite)
- FR-12 `block_ip` (Redis TTL), `lock_account`, `rate_limit`, `create_incident`, `notify` (Slack/Teams webhook), all idempotent and audited.
- FR-13 Response policy per rule/model (YAML), severity-based escalation, analyst override (unblock, unlock).
- FR-14 Spring Boot `responder` gateway enforces blocklist (403), rate limits, JWT/RBAC on admin routes.

### 6.5 API
- FR-15 FastAPI: `/health`, `/incidents`, `/incidents/{id}`, `/blocklist`, `/rules`, `/models`, `/triage/{incident_id}`; JWT auth, roles `analyst`, `admin`.

### 6.6 Attack lab and vulnerability assessment
- FR-16 `target-shop` v1 intentionally vulnerable (SQLi, XSS, weak auth/no rate limit, IDOR, security misconfig, verbose errors); v2 patched.
- FR-17 `lab/run_attacks.sh` runs guarded Nmap, sqlmap, Hydra, ZAP baseline/active, and scripted DoS against the lab only.
- FR-18 Burp Suite manual testing documented with screenshots; `docs/owasp-findings.md` lists each finding, evidence, detection that fired, and the v2 fix.
- FR-19 Wireshark/tshark captures of attacks are replayed and validated against network detections.

### 6.7 Visibility
- FR-20 Detections/incidents forwarded to Splunk Free via HEC; saved searches and a dashboard exported to `dashboards/splunk/`.
- FR-21 Prometheus metrics (events/sec, detections by technique, actions, latency) and a Grafana dashboard exported to `dashboards/grafana/`.
- FR-22 Removed (16 GB RAM laptop): Splunk provides search and retention; incidents also persist in PostgreSQL.

### 6.8 LLM triage agent
- FR-23 Summarizes an incident, maps to ATT&CK, suggests remediation, returns structured JSON.
- FR-24 Defenses: sanitize and delimit untrusted log fields, no tool/permission changes driven by log text, output schema validation, response actions never executed by the LLM directly (human/policy approval), cost and token caps, audit of prompts.
- FR-25 Prompt-injection test corpus (>= 15 strings embedded in log fields) with pass/fail reported in metrics.

### 6.9 DevSecOps and platform security
- FR-26 GitHub Actions: ruff, mypy, pytest+coverage, JUnit, Semgrep/CodeQL (SAST), Dependency-Check (SCA), Trivy (containers), Gitleaks (secrets), Checkov (Terraform/K8s), ZAP baseline (DAST) against target-shop.
- FR-27 TLS/mTLS between services in compose/K8s (dev CA), secrets via Vault dev or Docker secrets, least-privilege DB roles, audit log.
- FR-28 Terraform + kind manifests for the platform; `infra/` passes Checkov and is evaluable by Agent SecOps.
- FR-29 `docs/threat-model.md` (STRIDE for Sentinel itself) and `docs/runbook.md` (incident playbooks).

### 6.10 Evaluation
- FR-30 `evaluate.py` runs the full scenario and writes `results/metrics.json` with: per-class precision/recall/F1, FPR, PR-AUC (fraud), confusion matrices, events/sec, mean+p95 time-to-detect, mean+p95 time-to-respond, rule/technique counts, injection-test pass rate, test counts, SAST/SCA finding counts before/after fixes.
- FR-31 README Results table generated from `metrics.json` by script.

## 7. Non-functional
NFR-1 reproducible (seeds, pinned deps, one command) · NFR-2 target 1,000 eps for 60 s on a laptop (measure, report actual) ·
NFR-3 15+ Python tests and JUnit tests, coverage reported · NFR-4 lab-only attacks, no secrets in git ·
NFR-5 structured JSON logs; every detection has an explanation · NFR-6 docs complete (architecture, threat model, runbook, findings, write-up).

## 8. Success metrics (measured, sanity ranges only)
RF/XGBoost binary F1 0.95 to 0.99, FPR under 2% · Isolation Forest/autoencoder F1 0.5 to 0.85 · phishing model F1 above 0.9 ·
fraud PR-AUC reported honestly (highly imbalanced) · time-to-detect under 2 s local · block latency under 500 ms local · throughput measured at 1,000 eps.

## 9. Risks
| Risk | Mitigation |
|---|---|
| Scope is large | Strict ordered task list; each phase leaves a working system; commit per task |
| Toolchain friction (Kafka, Splunk, Zeek) | Pinned images; documented fallbacks (Redpanda for Kafka, OpenSearch-only if Splunk fails, tshark replay if Zeek fails) |
| Inflated ML numbers | Stratified split before scaling, per-class metrics, documented dataset limits |
| LLM misuse via logs | FR-24 defenses + injection corpus |
| Lab tooling misuse | Target guard in every attack script |

## 10. Build phases (all required; see TASKS.md)
P1 core pipeline + rules + ML + response + eval · P2 Spring Boot responder + vulnerable target + attack lab + OWASP report ·
P3 endpoint source, network capture, Splunk, Grafana · P4 phishing + fraud + autoencoder models ·
P5 LLM triage with injection defenses · P6 DevSecOps + platform security + Terraform/kind + docs + write-up.
