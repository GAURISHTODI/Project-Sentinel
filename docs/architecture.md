# Architecture

Sentinel is a detection and response platform for an e-commerce environment. Log events flow from
sources through Kafka into a rule and model engine, and from there into automatic responses, an
audit chain, dashboards, and an LLM triage agent that only suggests.

## Data flow

```
 app logs ──┐                      ┌─> detect/run.py (rules SEN-001..013, network model,
 auth logs ─┼─> logs.* topics ─> normalize ─> events.normalized ─┤   phishing URL model if enabled,
 endpoint ──┤   (Kafka)          (ingest)                        │   card-fraud model on transactions)
 network ───┘   Zeek/Suricata                                    │
 (pcap)         via normalize_network                            ├─> detections (Kafka)
                                                                 │      └─> respond/splunk_forward ─> Splunk HEC
                                                                 └─> respond/responder
                                                                        ├─ block_ip ─> Redis blocklist ─> responder gateway
                                                                        ├─ rate_limit ─> Redis
                                                                        ├─ lock_account ─> PostgreSQL locked_accounts
                                                                        ├─ create_incident ─> PostgreSQL incidents
                                                                        ├─ notify ─> webhook (Slack or Teams)
                                                                        └─ audit ─> PostgreSQL audit_log (hash chain)

 browser / analyst ─> FastAPI (JWT, RBAC) ─> incidents, blocklist, unlock, rules, models
 triage/run.py ─> LLM provider (mock by default, Gemini adapter) ─> schema-checked suggestion only
 detect/run.py ─> Prometheus /metrics (:8001) ─> Grafana dashboard
```

## Components

| Component | Where | Role |
|---|---|---|
| Traffic generator | `src/sentinel/generator` | Synthetic multi-source events with labelled campaigns (evaluation only) |
| Normalizers | `src/sentinel/ingest` | Turn each source into `NormalizedEvent`; untrusted input is length-capped and typed |
| Rule engine | `src/sentinel/detect/rules` | 13 Sigma-style YAML rules, each mapped to an ATT&CK technique |
| ML detectors | `src/sentinel/detect/ml` | Network XGBoost (binary and multi-class), phishing URL, card fraud; anomaly models trained but not yet wired in |
| Responder | `src/sentinel/respond` | Policy-driven, idempotent actions with a hash-chained audit log |
| Responder gateway | `responder/` (Spring Boot 3.5) | Enforces the blocklist and rate limits in front of the target, with JWT and RBAC |
| Target shop | `target-shop/` (Spring Boot 3.5) | Intentionally vulnerable v1 and fixed v2, switched by `SHOP_VERSION` |
| API | `src/sentinel/api` (FastAPI) | Incidents, blocklist, account unlock, rules and models; JWT and RBAC |
| Splunk | `dashboards/splunk`, `respond/splunk_forward.py` | Index, saved searches and dashboard as an app bundle; HEC forwarder |
| Grafana | `dashboards/grafana` | Provisioned Prometheus datasource and dashboard |
| Triage agent | `src/sentinel/triage` | Summarises an incident into a schema-checked report; no access to any action |
| Lab | `lab/` | Guarded attack scripts (Nmap, sqlmap, Hydra, ZAP, scripted DoS) run only on the internal `lab` network |

## Network and trust boundaries

Compose defines three networks. `backend` is internal, so the data plane has no internet route.
`edge` exists only so that services can publish ports on 127.0.0.1. `lab` is internal, and the
vulnerable target is attached only to it, behind the gateway. The gateway's address is the only one
the target trusts for forwarded client addresses.

## Data stores

- **Kafka** (KRaft): `logs.app`, `logs.auth`, `logs.endpoint`, `events.normalized`, `detections`.
- **Redis**: the blocklist, rate-limit counters, and detector windows.
- **PostgreSQL**: incidents, locked accounts, users, and the audit log. The audit log is append-only
  (a trigger), and its hash chain detects edits made by someone who can disable the trigger.
- **Splunk**: detections, incidents and audit rows forwarded over HEC, indexed in `sentinel`.

## Security controls in place

- Each service connects to PostgreSQL as its own least-privilege role. The evaluation harness keeps the owner.
- PostgreSQL requires verified TLS for remote clients, using a dev CA. Kafka and Redis are not encrypted.
- Compose credentials are Docker secrets for Postgres, Redis and the responder. Host-side processes still read `.env`.
- Every API response carries nosniff, DENY framing, no-store, no-referrer and a restrictive CSP.
- Log content is treated as untrusted everywhere: at ingest, in rules, in ML inputs, in the triage prompt, and in dashboards.

## Deployment profiles

Compose defines two profiles. `core` runs the data plane, the target and the gateway. `viz` adds Splunk,
Prometheus and Grafana. The lab tools run from their own images through the guarded scripts in `lab/`, not as a
compose profile. `infra/k8s` holds a platform namespace with default-deny network policies that have been checked
with Checkov but not deployed to a cluster. The profiles are kept separate because the 16 GB development machine
cannot run everything at once.
