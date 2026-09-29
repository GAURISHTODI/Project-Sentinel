# CLAUDE.md — Sentinel (FULL PROJECT)

# HARDWARE CONSTRAINTS (read first)
Dev machine: 16 GB RAM, 512 GB SSD, CPU only, NO GPU. Rules: keep Docker/WSL memory under 10 GB; use docker compose profiles (`core`, `viz`, `k8s`) and never run everything at once; NO OpenSearch (Splunk covers search); CPU-only PyTorch; fraud model uses the Kaggle credit-card fraud dataset (not IEEE-CIS); load CIC-IDS2017 file by file with float32 dtypes, sample to 200k rows, free the rest; Kafka and JVM services use -Xmx512m; the LLM triage agent uses an API, never a local model.


Claude Code reads this at the start of every session. The target is the COMPLETE platform described in PRD.md.
Every phase in TASKS.md is a required deliverable. Build them all, in order.

## What this project is
Sentinel is an end-to-end, AI-driven threat detection and automated response platform for an e-commerce
environment (Walmart-style: credential stuffing, account takeover, injection, scanning, bot/DoS, phishing, fraud).
Multi-source logs (app, auth, network, Windows endpoint) -> Kafka -> detection (Sigma-style rules mapped to
MITRE ATT&CK + ML models) -> automated response (SOAR-lite) -> visibility (Splunk, Grafana) -> LLM triage agent,
all secured and shipped through a DevSecOps pipeline, and validated by a real attack lab against our own vulnerable target.

## Hard rules
1. **Metrics are measured, never invented.** Numbers in README.md come only from `results/metrics.json`,
   written by `python -m sentinel.eval.evaluate`. Unmeasured = "TBD".
2. **README status checklist is updated as each feature lands** (code + test + working demo).
3. **Attack tooling targets only our local Docker lab network** (`lab`). Every attack script must include a guard that
   aborts if the target is not a lab container/localhost. No malware. No real-world exploit chains. Textbook test payloads only.
4. **No secrets in git.** `.env` gitignored, `.env.example` committed, secrets via Docker secrets / Vault dev mode.
5. **Small verifiable steps.** After each task: run tests, run the demo command, show real output, commit.
6. **Report bad results honestly.** Do not tune data or thresholds to inflate a metric; document limitations.
7. **Treat all log/event content as untrusted input** everywhere (rules, ML, LLM agent, dashboards).

## Tech stack (final)
- **Detection/ML/API (Python 3.11):** FastAPI, pydantic, scikit-learn, XGBoost, PyTorch (autoencoder), pandas, MLflow, confluent-kafka, redis-py, psycopg
- **Java 21 + Spring Boot 3:** `responder` gateway (blocklist enforcement, JWT/RBAC, rate limiting) and `target-shop` vulnerable e-commerce target (intentionally vulnerable v1, patched v2)
- **Data plane:** Kafka (KRaft), Redis 7, PostgreSQL 16 (Splunk provides search; no OpenSearch)
- **Visibility:** Splunk Free via HEC, Prometheus, Grafana
- **Network/endpoint sources:** Zeek or Suricata (pcap replay), tshark/Wireshark, Sysmon/ETW-style Windows logs (WinPulse format)
- **Attack lab (lab-only):** Nmap, sqlmap, Hydra, OWASP ZAP, Burp Suite (manual, documented), custom scripted scenarios
- **LLM triage:** Anthropic API (Claude) or Azure OpenAI, with prompt-injection defenses and cost caps
- **Platform/DevSecOps:** Docker, Docker Compose, Kubernetes (kind), Terraform, GitHub Actions, Semgrep/CodeQL, Trivy, Gitleaks, OWASP Dependency-Check, Checkov, ZAP baseline, Vault (dev mode) or Docker secrets
- **Quality:** pytest, pytest-cov, JUnit 5, ruff, mypy, pre-commit

## Repo layout
```
sentinel/
  src/sentinel/
    common/        schema.py, config.py, logging, security helpers
    generator/     synthetic multi-source log generator + attack scenarios
    ingest/        Kafka producers/consumers, per-source normalizers (app, auth, zeek/suricata, windows)
    detect/
      rules/       engine + rules/*.yaml (Sigma-style, ATT&CK-mapped)
      ml/          train_network.py, train_anomaly.py, train_phishing.py, train_fraud.py, predictor.py, registry
      engine.py
    respond/       actions.py, policy.py, notify.py (Slack/Teams webhook)
    triage/        LLM agent, sanitizer.py, guardrails, tests with injection corpus
    api/           FastAPI: incidents, blocklist, rules, models, auth (JWT + RBAC)
    eval/          evaluate.py, plots, metrics writer, README updater
  responder/       Spring Boot 3 gateway
  target-shop/     vulnerable target app (v1 vulnerable, v2 fixed)
  lab/             attack scripts (guarded), pcap capture/replay, zeek config
  windows/         WinPulse/Sysmon-style log exporter + sample logs
  dashboards/      grafana/, splunk/
  infra/           terraform/, k8s/ (kind), vault/
  tests/
  docs/            architecture.md, owasp-findings.md, threat-model.md, runbook.md, writeup.md
  results/         metrics.json, confusion matrices, plots
  .github/workflows/
  docker-compose.yml
```

## Commands
```
docker compose --profile core up -d      # add --profile viz for Splunk/Grafana only when needed
pip install -e ".[dev]"
pytest -q  &&  (cd responder && mvn -q test)
python -m sentinel.generator.run --eps 1000 --duration 60
python -m sentinel.detect.ml.train_network --sample 200000
python -m sentinel.eval.evaluate
bash lab/run_attacks.sh            # lab-only, guarded
ruff check . && mypy src
```

## Conventions
- Type hints, pydantic at boundaries, no bare `except`.
- Every rule YAML: `id`, `title`, `attack_id`, `severity`, `condition`, `response`.
- Every Detection: `event_id`, `rule_id | model_name`, `attack_id`, `score`, `timestamp_detected`, `explanation`.
- Detectors never read the `label` field (evaluation only).
- Commits: `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `sec:`.

## Definition of done (per task)
Code + tests + demo command works + README checklist ticked + `pytest -q` green + committed.
