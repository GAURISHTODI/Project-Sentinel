<!-- Publish only after every number below is replaced with values from results/metrics.json. Delete this comment. -->

# Sentinel

**AI-driven threat detection and automated response platform for e-commerce environments.**

Sentinel ingests logs from four sources, detects attacks with ATT&CK-mapped rules and machine learning, responds automatically through a Spring Boot gateway, and gives analysts visibility in Splunk and Grafana. It includes a live attack lab, a hardened LLM triage agent, and a DevSecOps pipeline.

`Java 21` `Spring Boot` `Python 3.11` `FastAPI` `scikit-learn` `XGBoost` `PyTorch` `Kafka` `Redis` `PostgreSQL` `Splunk` `Grafana` `Docker` `Kubernetes` `GitHub Actions` `MITRE ATT&CK`

## Highlights

| | |
|---|---|
| **Ingestion** | 4 log sources (app, auth, network/Zeek, Windows endpoint) through Kafka, throughput TBD |
| **Detection** | 12 planned Sigma-style rules mapped to MITRE ATT&CK, plus 6 planned ML models (built so far: see status) |
| **Network IDS accuracy** | TBD (CIC-IDS2017) |
| **Response** | 5 planned automated actions enforced by a Spring Boot gateway with JWT/RBAC |
| **Speed** | Block latency TBD, mean time to detect TBD |
| **Vulnerability assessment** | Findings TBD |
| **LLM safety** | Injection suite pass rate TBD |
| **DevSecOps** | Scanners in CI TBD, test count TBD |

## Status

A feature is ticked only when its code, tests and a working demo exist.

- [x] T1 Scaffold + infra (Kafka KRaft, Redis, PostgreSQL, compose profiles)
- [x] T2 Schema + generator (20 tests; live Kafka publish and round trip verified)
- [x] T3 Rule engine (SEN-001..009; verified on real Redis)
- [x] T4 Network ML (RF + XGBoost binary, XGBoost multi-class, MLflow, model card; metrics TBD in README until T6)
- [x] T5 Detection engine + response (rules + ML, policy YAML, 5 idempotent actions, hash-chained audit log; live Kafka/Redis/Postgres demo run)
- [x] T6 API (JWT + RBAC) + evaluation harness (live and in-process) + CI workflow
- [x] T7 Vulnerable target (v1 vulnerable + v2 fixed twin, Kafka logs, normalizer, isolated lab network; 34 JUnit tests)
- [x] T8 Spring Boot responder gateway (blocklist 403, rate limit 429, JWT/RBAC, path-normalised proxy; 61 JUnit tests; live block demo)
- [x] T9 Attack lab (Nmap, sqlmap, Hydra, ZAP baseline+active, scripted DoS; every attack verified live through the real detection+response pipeline)
- [x] T10 OWASP findings + fixes (14 findings in v1, all 14 closed in v2, each re-verified live against the real container)
- [x] T11 Endpoint source (WinPulse format, real exporter verified against this machine's own Event Log, SEN-010..012, endpoint anomaly features, 29 tests on sample logs)
- [x] T12 Network source (real tshark/Zeek/Suricata capture against live lab attacks via lab/06_capture_attack.sh; SEN-004 and SEN-013 verified firing on genuinely pcap-derived data, not synthetic)
- [x] T13 Splunk (HEC forwarder sent 4,437/4,437 real detections; incident and audit counts match Postgres exactly; sentinel index, 4 saved searches and dashboard provisioned from the mounted app bundle and verified via Splunk's REST API)
- [x] T14 Grafana (detect service exports events, detections by ATT&CK technique, actions by outcome and latency histograms on :8001; Prometheus scrapes it live as up; provisioned "Sentinel detection and response" dashboard renders all 8 panel queries with real series)
- [x] T15 Anomaly models (Isolation Forest and PyTorch autoencoder trained on benign CIC-IDS2017 traffic only; threshold set on held-out benign rows for 1% FPR; on the untouched test split the autoencoder reaches 50% recall and Isolation Forest 15%, reported separately from the supervised models)
- [x] T16 Phishing URL classifier (PhiUSIIL, 235,795 URLs, lexical features from the URL string only, host-disjoint test split; F1 0.990 on that split, but it flags legitimate URLs with a trailing slash 92% of the time, so the detector is opt-in and not a production control; see docs/known-limitations.md)
- [x] T17 Fraud model (XGBoost with class weights, no resampling; ULB credit-card data, 284,807 transactions; test PR-AUC 0.872, ROC-AUC 0.973; recall 0.867 at a validation-chosen 0.80 precision target, which gave 0.794 precision on test; detector fires on transaction events, verified live on real held-out rows)
- [ ] T18 Triage agent
- [ ] T19 Injection test suite
- [ ] T20 CI security gates
- [ ] T21 Platform security
- [ ] T22 Terraform + Kubernetes (kind)
- [ ] T23 Final evaluation
- [ ] T24 Documentation

## Architecture

```
 Sources                 Ingestion            Detection                        Response / Visibility
┌─────────────┐      ┌──────────────┐    ┌──────────────────────────┐    ┌───────────────────────────┐
│ App / Auth  │─┐    │ Kafka        │    │ Sigma-style rules        │    │ Spring Boot gateway       │
│ Zeek        │─┼──▶ │ Normalizers  │──▶ │ (ATT&CK-mapped)          │──▶ │ Redis blocklist, lockout  │
│ Windows EP  │─┤    │ events.norm. │    │ ML: RF, XGBoost,         │    │ Rate limiting, incidents  │
│ target-shop │─┘    └──────────────┘    │ IForest, autoencoder,    │    │ Splunk HEC, Grafana       │
└─────────────┘                          │ phishing URL, fraud      │    │ LLM triage (guarded)      │
                                         └────────────┬─────────────┘    └───────────────────────────┘
                                                      ▼
                                             FastAPI (JWT + RBAC)

 Attack lab: Nmap, sqlmap, Hydra, ZAP, Burp ──▶ target-shop v1 (vulnerable) / v2 (fixed)
 DevSecOps:  Semgrep/CodeQL · Trivy · Gitleaks · Dependency-Check · Checkov · ZAP · Terraform/kind
```

## Features

### Multi-source ingestion
Four sources are normalized into a single event schema and published to Kafka: application and auth logs, network flows and alerts from Zeek, and Windows endpoint events (process creation, service installs, PowerShell script blocks) from a WinPulse/Sysmon-style exporter.

### Rule-based detection
12 planned Sigma-style YAML rules with Redis sliding windows, mapped to MITRE ATT&CK.

| Rule | Detection | ATT&CK |
|---|---|---|
| SEN-001 | Brute-force login | T1110 |
| SEN-002 | SQL injection | T1190 |
| SEN-003 | Cross-site scripting | T1190 |
| SEN-004 | Port scan | T1046 |
| SEN-005 | Scanner user-agent | T1595 |
| SEN-006 | Valid-account abuse (new geo/IP) | T1078 |
| SEN-007 | HTTP flood | T1499 |
| SEN-008 | Credential stuffing | T1110.004 |
| SEN-009 | Path traversal | T1190 |
| SEN-010 | Suspicious process spawn | T1059 |
| SEN-011 | Encoded PowerShell | T1059.001 |
| SEN-012 | New service persistence | T1543 |

### Machine learning
Six models, all trained on CPU:

- **Network intrusion detection:** Random Forest and XGBoost on a stratified 200,000-row CIC-IDS2017 sample, split before scaling with a fixed seed.
- **Anomaly detection:** Isolation Forest and a PyTorch autoencoder trained on benign traffic.
- **Phishing URL classifier:** lexical features such as length, entropy, subdomain count and TLD.
- **Fraud model:** Kaggle credit-card fraud data with class weighting for the heavy imbalance.

Every model ships with a `model_card.json` recording its dataset, sample size, seed and metrics.

### Automated response
Five actions run through a YAML response policy, and each is idempotent and audited:

1. Redis IP blocklist with TTL
2. Account lockout
3. Per-IP rate limiting
4. Incident record in PostgreSQL
5. Alerting via Slack/Teams webhook

The Spring Boot gateway enforces the blocklist (HTTP 403), rate limits, and JWT/RBAC on admin routes.

### Attack lab and vulnerability assessment
`target-shop` v1 is a deliberately vulnerable e-commerce app covering SQL injection, reflected and stored XSS, IDOR, weak authentication, missing rate limiting, and security misconfiguration. The lab attacks it with Nmap, sqlmap, Hydra and OWASP ZAP, with manual testing in Burp Suite, and captures traffic with Wireshark/tshark for pcap validation. All findings will be documented in `docs/owasp-findings.md` with the Sentinel detection that fired, then closed in `target-shop` v2 and re-tested.

### Visibility
Detections and incidents are forwarded to Splunk via HEC, with saved searches and a dashboard. Prometheus and Grafana track events per second, detections by ATT&CK technique, response actions and latency.

### LLM triage agent
The agent summarizes an incident, maps it to ATT&CK and suggests remediation as schema-validated JSON. Log content is treated as attacker-controlled:

- Untrusted fields are sanitized and delimited.
- Log text can never change tools or permissions.
- The LLM never executes response actions itself.
- Token and cost caps are enforced, and every prompt is audited.

A test suite embeds 15+ prompt-injection strings in user-agent, path, username and command-line fields, and the pass rate is recorded in `results/metrics.json` (TBD).

### DevSecOps and platform security
GitHub Actions runs Semgrep/CodeQL (SAST), Dependency-Check (SCA), Trivy (containers), Gitleaks (secrets), Checkov (IaC) and ZAP baseline (DAST), alongside Python and JUnit tests. Services use TLS with a dev CA, secrets live in Vault or Docker secrets, and database roles are least-privilege. Terraform and Kubernetes (kind) manifests deploy the platform, and its infrastructure is checked by the [Agent SecOps](https://github.com/GAURISHTODI/Agent-SecOps) gate.

## Results

Generated by `python -m sentinel.eval.evaluate` into `results/metrics.json`.

<!-- METRICS:START -->
| Metric | Result |
|---|---|
| Evaluation run | live mode, 60,000 labeled events, 1,000 events/s target, seed 42, commit `2c62bef` |
| Sustained throughput | 1,016 events/s over 59.05 s; service processed 60,000 of 60,000 |
| Attack campaign recall (rule-based) | 0.975 over 448 campaigns in 12 covered scenarios; no rule yet for: none |
| False alerts on benign events | 7 of 54,000 (rate 0.00013) |
| Time to detect (attack start to alert) | mean 310 ms, p95 641 ms (n=437) |
| Pipeline latency per detection | mean 294 ms, p95 648 ms (n=2619) |
| Time to respond (attack start to enforcement) | mean 391 ms, p95 760 ms (n=177) |
| Network IDS, Random Forest (CIC-IDS2017 held-out split) | F1 0.9953, precision 0.9969, recall 0.9938, FPR 0.0007, PR-AUC 0.9997 |
| Network IDS, XGBoost (CIC-IDS2017 held-out split) | F1 0.9969, precision 0.9963, recall 0.9975, FPR 0.0008, PR-AUC 0.9998 |
| Network IDS, multi-class XGBoost | macro-F1 0.8898, accuracy 0.9983 |
| Anomaly models | measured, see metrics.json |
| Phishing URL model | measured, see metrics.json |
| Fraud model | measured, see metrics.json |
| Prompt-injection suite | TBD |
| OWASP findings, v1 to v2 | 14 → 0 (re-verified live: sqlmap, Hydra, ZAP full active scan, 36 JUnit tests) |
| CI security scanners | TBD |
| Automated tests | 259 Python |
<!-- METRICS:END -->

**Limitations:** CIC-IDS2017 and the public phishing and fraud datasets are curated, so real-world traffic will differ. The anomaly models are unsupervised and are reported separately from the supervised classifier. Synthetic logs approximate production telemetry and do not replace it.

## Quick start

```bash
git clone https://github.com/GAURISHTODI/Project-Sentinel && cd Project-Sentinel
cp .env.example .env
docker compose --profile core up -d
pip install -e ".[dev]"

python -m sentinel.detect.ml.train_network --sample 200000
python -m sentinel.generator.run --eps 1000 --duration 60
python -m sentinel.eval.evaluate
bash lab/run_attacks.sh        # lab-only, guarded
```

Requirements: Docker with Compose v2, Python 3.11+, Java 21, Maven. About 10 GB of RAM allocated to Docker is enough for the core profile.

## Repository layout

```
src/sentinel/    detection engine, ML, response, triage, API, evaluation
responder/       Spring Boot gateway
target-shop/     vulnerable e-commerce target (v1) and fixed version (v2)
lab/             guarded attack scripts, pcap capture and replay
windows/         endpoint log exporter and samples
dashboards/      Splunk and Grafana exports
infra/           Terraform, Kubernetes (kind), Vault
docs/            architecture, threat model, runbook, OWASP findings, write-up
```

## Documentation
[Architecture](docs/architecture.md) · [Threat model](docs/threat-model.md) · [Runbook](docs/runbook.md) · [OWASP findings](docs/owasp-findings.md) · [Write-up](docs/writeup.md)

## Ethics and scope
All attack tooling targets the local Docker lab only, enforced by a guard in every script. The project contains no malware.

## License
MIT
