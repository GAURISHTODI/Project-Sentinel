# HARDWARE CONSTRAINTS (read first)
Dev machine: 16 GB RAM, 512 GB SSD, CPU only, NO GPU. Rules: keep Docker/WSL memory under 10 GB; use docker compose profiles (`core`, `viz`, `k8s`) and never run everything at once; NO OpenSearch (Splunk covers search); CPU-only PyTorch; fraud model uses the Kaggle credit-card fraud dataset (not IEEE-CIS); load CIC-IDS2017 file by file with float32 dtypes, sample to 200k rows, free the rest; Kafka and JVM services use -Xmx512m; the LLM triage agent uses an API, never a local model.

# TASKS.md — FULL build order (all phases required)

Start every session: *"Read CLAUDE.md, PRD.md and TASKS.md. We are on task N. Check git log and repo state."*
After each task: run tests, run the demo command, show real output, tick the README checklist, commit.

---
## PHASE 1 — Core pipeline

**T1 Scaffold + infra.** pyproject.toml (deps per CLAUDE.md), src layout, .gitignore, .env.example, docker-compose with Kafka (KRaft), Redis 7, PostgreSQL 16, healthchecks, split into compose profiles `core` (Kafka, Redis, Postgres, API, gateway, target), `viz` (Splunk, Grafana, Prometheus) and `k8s`; set Kafka/JVM heaps to 512m; `sql/init.sql` for incidents, locked_accounts, audit_log, users/roles. Show `docker compose ps`.

**T2 Schema + generator.** `NormalizedEvent` (event_id, source app/auth/network/endpoint, timestamp_generated, src_ip, user, method, path, status, user_agent, dst_port, flow_features, process fields for endpoint, label for eval only). Generator with `--eps --duration --attack-mix` producing benign traffic plus labeled brute force, credential stuffing, SQLi, XSS, path traversal, port scan, DoS, endpoint scenarios. Publish to Kafka. Tests.

**T3 Rule engine.** YAML Sigma-style rules, Redis sliding windows, hot reload, ATT&CK mapping; write SEN-001..SEN-009 (network/app/auth). Positive/negative tests including benign bursts. Detectors never read `label`.

**T4 Network ML.** Load CIC-IDS2017, clean, stratified 200k sample (seed 42), split before scaling, train RandomForest + XGBoost (binary) and a multi-class variant; MLflow tracking; model_card.json; predictor. Print classification report and confusion matrix. Report honestly.

**T5 Detection engine + response.** Consume `events.normalized`, run rules + ML, emit Detection with explanation. Actions: block_ip (Redis TTL), lock_account, rate_limit, create_incident, notify (Slack/Teams webhook, mockable). YAML response policy, idempotency, audit log. Tests.

**T6 API + evaluation harness.** FastAPI incidents/blocklist/rules/models with JWT + RBAC (analyst, admin). `evaluate.py` runs a labeled 60 s scenario at 1,000 eps and writes `results/metrics.json`; `scripts/update_readme_metrics.py` fills README Results from it. CI (ruff, mypy, pytest).

## PHASE 2 — Gateway, target and attack lab

**T7 Vulnerable target.** `target-shop` (Java/Spring Boot or reuse CoreTest services) v1 intentionally vulnerable: SQLi login/search, reflected+stored XSS, no rate limit, weak password storage, IDOR, verbose errors, security misconfig. Emits structured access/auth logs to Kafka. Runs only on the `lab` network.

**T8 Spring Boot responder gateway.** Java 21 gateway in front of target-shop: checks Redis blocklist (403), per-IP rate limiting, JWT validation, RBAC on admin endpoints. JUnit 5 tests. Compose-integrated.

**T9 Attack lab.** `lab/run_attacks.sh` (with target guard that aborts unless target is a lab container/localhost): Nmap scans, sqlmap, Hydra brute force, ZAP baseline + active scan, scripted DoS, XSS payloads. Confirm each attack produces the expected detection and response through the real pipeline. Save results.

**T10 OWASP findings + fixes.** `docs/owasp-findings.md`: per finding — OWASP category, evidence (tool output, Burp screenshots placeholders for me to add), which Sentinel detection fired, severity. Then build `target-shop` v2 with fixes (parameterized queries, output encoding, bcrypt/argon2, rate limiting, generic errors, secure headers) and re-run attacks to show findings closed. Record before/after counts.

## PHASE 3 — Sources and visibility

**T11 Endpoint source.** `windows/` exporter that emits Sysmon-style events (process create, network connect, service install, PowerShell script block) in WinPulse format plus sample logs; normalizer; rules SEN-010..012; endpoint anomaly features (command-line entropy, rare parent-child). Tests with sample logs.

**T12 Network source.** Capture attack traffic with tshark to pcap; run Zeek or Suricata over pcap (fallback: tshark-derived flow features); normalizer for conn.log/eve.json; validate port-scan and DoS detections fire on the pcap. Document Wireshark filters used.

**T13 Splunk.** Splunk Free container with HEC; forward detections/incidents; saved searches (top attackers, techniques over time, failed logins, blocked IPs) and a dashboard exported to `dashboards/splunk/`. Fallback: OpenSearch-only with note.

**T14 Grafana.** Prometheus metrics endpoint (events/sec, detections by ATT&CK id, actions, latencies) and a provisioned Grafana dashboard JSON. No OpenSearch (RAM limits); incidents persist in PostgreSQL and Splunk.

## PHASE 4 — More ML

**T15 Anomaly models.** Isolation Forest + PyTorch autoencoder trained on benign flows; threshold selection on validation set; report separately from supervised.

**T16 Phishing URL classifier.** Public dataset, lexical features (length, entropy, digits, subdomains, TLD, special chars), train/eval, integrate as a detector on URLs in app/email-like events.

**T17 Fraud model.** Kaggle credit-card fraud dataset (284k rows), imbalance handling (class weights/SMOTE on train only), PR-AUC and recall at fixed precision; integrate on transaction events. Report honestly.

## PHASE 5 — LLM triage

**T18 Triage agent.** Summarize incident, map to ATT&CK, suggest remediation, return schema-validated JSON. Defenses: sanitize/delimit untrusted log fields, strip control text, never let log content change tools or permissions, LLM never executes actions (policy/human approves), token+cost caps, prompt audit log. Provide a mock LLM for tests.

**T19 Injection test suite.** 15+ prompt-injection strings placed in user-agent, path, username, process command line; automated test asserts the agent's output stays on-schema and no action escalates. Add the pass rate to metrics.json.

## PHASE 6 — DevSecOps, platform security, docs

**T20 CI security gates.** GitHub Actions: Semgrep/CodeQL, Dependency-Check, Trivy (images), Gitleaks, Checkov, ZAP baseline on target-shop v2, plus tests/coverage. Record finding counts before/after fixes.

**T21 Platform security.** mTLS or TLS between services with a dev CA, Vault dev mode or Docker secrets, least-privilege DB roles, audit log integrity, security headers on APIs.

**T22 Terraform + Kubernetes (kind).** Terraform for supporting infra and K8s manifests for the platform; pass Checkov; run our Agent SecOps gate over the plan and record the verdict.

**T23 Final evaluation.** Run full evaluate.py across all components; regenerate README results; generate confusion-matrix and latency plots into `results/`.

**T24 Documentation.** `docs/architecture.md` (with diagram), `docs/threat-model.md` (STRIDE), `docs/runbook.md` (playbooks per detection), `docs/writeup.md` (methods, results, limitations, AI-in-security trends, zero-day considerations). Final README polish with a demo script and GIF/screenshot placeholders.

---
## Resume numbers come from
`results/metrics.json`, `pytest -q`/`mvn test` counts, CI scan summaries, and the README checklist.
