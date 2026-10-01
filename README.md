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
- [ ] T7 Vulnerable target
- [ ] T8 Spring Boot responder gateway
- [ ] T9 Attack lab
- [ ] T10 OWASP findings + fixes
- [ ] T11 Endpoint source
- [ ] T12 Network source
- [ ] T13 Splunk
- [ ] T14 Grafana
- [ ] T15 Anomaly models
- [ ] T16 Phishing URL classifier
- [ ] T17 Fraud model
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
| Evaluation run | live mode, 60,000 labeled events, 1,000 events/s target, seed 42, commit `2772cf1` |
| Sustained throughput | 1,017 events/s over 59.01 s; service processed 60,000 of 60,000 |
| Attack campaign recall (rule-based) | 0.907 over 118 campaigns in 9 covered scenarios; no rule yet for: endpoint_powershell, endpoint_service, endpoint_spawn |
| False alerts on benign events | 7 of 54,000 (rate 0.00013) |
| Time to detect (attack start to alert) | mean 202 ms, p95 230 ms (n=107) |
| Pipeline latency per detection | mean 98 ms, p95 192 ms (n=1747) |
| Time to respond (attack start to enforcement) | mean 266 ms, p95 964 ms (n=70) |
| Network IDS, Random Forest (CIC-IDS2017 held-out split) | F1 0.9953, precision 0.9969, recall 0.9938, FPR 0.0007, PR-AUC 0.9997 |
| Network IDS, XGBoost (CIC-IDS2017 held-out split) | F1 0.9969, precision 0.9963, recall 0.9975, FPR 0.0008, PR-AUC 0.9998 |
| Network IDS, multi-class XGBoost | macro-F1 0.8898, accuracy 0.9983 |
| Anomaly models | TBD |
| Phishing URL model | TBD |
| Fraud model | TBD |
| Prompt-injection suite | TBD |
| OWASP findings, v1 to v2 | TBD |
| CI security scanners | TBD |
| Automated tests | 144 Python |
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
