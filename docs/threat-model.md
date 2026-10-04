# Threat model (STRIDE)

Scope: the Sentinel platform as built in this repository, from log ingestion to the analyst API and
the responder gateway that fronts the target. Status uses three values: **in place** (built and tested),
**partial** (built, but not covering the whole threat), and **open** (not built).

Assumptions: the developer laptop is trusted; the lab network is isolated from the internet; the
attack tools are only ever pointed at the lab. Log content, user agents, paths and command lines come
from untrusted clients and are never trusted.

## Assets

1. The detection and response decisions, and the blocklist that enforces them.
2. The incident and audit records (evidence).
3. Analyst credentials and the JWT signing secret.
4. The database, Kafka and Redis, which hold the above.
5. The target application, which is deliberately vulnerable in v1.

## Data flows and trust boundaries

- Clients to the gateway and target (untrusted to trusted).
- Log sources to Kafka (untrusted content, trusted transport on the internal network).
- Analyst to the API (authenticated; RBAC).
- Services to PostgreSQL, Redis and Kafka (internal; PostgreSQL is TLS-only).
- Sentinel to Splunk and the LLM provider (outbound; the LLM is treated as untrusted output).

## STRIDE by component

### Ingestion (log sources and normalizers)

| Threat | Example | Control | Status |
|---|---|---|---|
| Spoofing | A forged log source feeds false events | Sources are internal to the lab; no authentication between them | open |
| Tampering | Crafted fields change rule outcomes | Schema validation with length caps and a typed model; a poison message is counted and dropped, never crashes the loop | in place |
| Denial of service | Flood of log lines | Bounded per-key windows; the O(n²) window case is documented as a known limit (T12) | partial |
| Information disclosure | Logs carry secrets | The evaluation label is stripped before any detector runs; secrets are not logged | partial (no secret-scanning of log content) |

### Detection (rules and models)

| Threat | Example | Control | Status |
|---|---|---|---|
| Tampering | An attacker tunes traffic to stay under thresholds | Thresholds are fixed in YAML and documented; the lab measures the false-negative rate | partial |
| Tampering | Injection text in a field steers a model | Models take numeric features only; the triage prompt is separate and fenced | in place |
| Repudiation | Who decided what | Every detection is an incident with its rule id and event id | in place |
| Denial of service | Many distinct attackers | Detections do not block the pipeline; the responder runs after publish | partial |

### Response (responder and blocklist)

| Threat | Example | Control | Status |
|---|---|---|---|
| Spoofing | A client forges the forwarded address to evade blocks | The target trusts only the gateway's address for forwarded addresses | in place |
| Tampering | An analyst's override is undone without record | Actions are audited in a hash chain; the audit table is append-only (trigger) | partial (a privileged user can disable the trigger; the chain detects it) |
| Repudiation | An unlock with no record | The API audits unlocks with the acting user | in place |
| Elevation of privilege | A detection role edits audit rows | The detect role has INSERT only on the audit log and no UPDATE or DELETE; trigger blocks both for all roles | in place |
| Denial of service | Mis-triggered block of a legitimate address | Blocks have TTLs; policy-driven; loopback and link-local ranges are protected by policy; the cooldown stops repeats | partial (only the protected ranges are exempt; a customer address range is not yet listed) |

### Analyst API

| Threat | Example | Control | Status |
|---|---|---|---|
| Spoofing | Forged tokens | HS256 JWT with a minimum-length secret, algorithm pinned on decode; forged and unsigned tokens are rejected (tested) | in place |
| Tampering | Analyst changes severity | The API role can update only incident status; severity changes are refused by the database (tested) | in place |
| Repudiation | Unattributed changes | Each API action is audited with the username | in place |
| Information disclosure | Errors leak internals | Unhandled errors return a generic 500; responses carry strict headers | in place |
| Elevation of privilege | Viewer performs admin actions | RBAC roles checked per route (tested) | in place |
| Denial of service | Login brute force | Login throttling (tested) | in place |

### Data stores and transport

| Threat | Example | Control | Status |
|---|---|---|---|
| Spoofing | Rogue database server | Postgres clients verify the server certificate against the dev CA | partial (dev CA only) |
| Information disclosure | Sniffing traffic | Postgres: TLS only from remote clients. Kafka and Redis: plaintext on internal networks | partial |
| Tampering | Changing rows directly | Least-privilege roles per service; the owner is used only by the evaluation harness | partial (the owner still exists and is powerful) |
| Information disclosure | Credentials in git or images | Compose secrets are files under a gitignored directory; gitleaks runs in CI with reviewed allowlist entries | partial (host processes still read `.env`) |

### Target application (intentionally vulnerable v1)

The v1 vulnerabilities (SQL injection, path traversal, weak password storage, reflected XSS) are the
attack surface for the lab. They are documented with finding IDs in `docs/owasp-findings.md`, and each
has a v2 fix that is re-verified against the live container. v1 is never exposed outside the lab network.

### Supply chain and build

| Threat | Example | Control | Status |
|---|---|---|---|
| Tampering | A compromised action or dependency | Actions pinned to commit SHAs; Trivy, Dependency-Check and Checkov run in CI | partial (Dependency-Check and CodeQL not yet run locally) |
| Tampering | Stale images run in production | CI packages jars before building images | in place |

## Threats outside the current scope

- Analyst workstation compromise.
- Physical access to the laptop.
- A real-world adversary using techniques that are not in the lab's scripts. The detection rules
  cover the techniques listed in the rule files, and the anomaly models are not yet live.

## Residual risk, in order

1. The database owner is powerful and is still used by the evaluation harness.
2. Host-side processes read credentials from `.env`.
3. Kafka and Redis traffic is unencrypted on the internal networks.
4. Rules and models can be evaded by an adversary who knows the thresholds.
5. A mis-tuned rule can block a real user. Only loopback and link-local ranges are protected by policy, so
   every customer address range would need to be listed before blocks are enabled on real traffic.
