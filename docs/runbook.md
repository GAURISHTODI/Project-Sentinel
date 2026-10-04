# Runbook

One playbook per detection, then the ML detectors and the triage agent. Each playbook says what fires,
what the platform already does, what an analyst should check, and how to clear a false positive. Commands
assume the core stack is running and the API is started (`python -m sentinel.api.main`, port 8080 unless `API_PORT` is set).

## Common commands

Get a token (replace the credentials; use an analyst account):

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/auth/token \
  -H 'content-type: application/json' -d '{"username":"analyst","password":"..."}' \
  | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
```

Open incidents, newest first:

```bash
curl -s -H "authorization: Bearer $TOKEN" 'http://127.0.0.1:8080/incidents'
```

Blocked addresses (the gateway enforces these; each entry is a Redis key `sen:blocklist:<ip>` with a TTL):

```bash
curl -s -H "authorization: Bearer $TOKEN" 'http://127.0.0.1:8080/blocklist'
curl -s -X DELETE -H "authorization: Bearer $TOKEN" 'http://127.0.0.1:8080/blocklist/203.0.113.9'
```

Unlock a locked account:

```bash
curl -s -X POST -H "authorization: Bearer $TOKEN" 'http://127.0.0.1:8080/accounts/alice/unlock'
```

Check the audit chain has not been edited (the owner can run this against the database):

```sql
SELECT id, ts, actor, action, target FROM audit_log ORDER BY id DESC LIMIT 20;
```

## Rules

### SEN-001 Brute-force login against one account (T1110, high)

- **Fires when** one account sees a burst of failed logins from one source.
- **Platform already does:** blocks the source for 3600 s, locks the account, creates an incident, notifies.
- **Check:** whether the account owner was locked out legitimately (forgotten password, a retry loop in a client).
  Look at the source's other incidents in `/incidents` and the audit rows for the same source.
- **Contain further:** if the source is not a known client, leave the block and reset the password through the
  account owner. If it is a known client, unblock the source and unlock the account after the owner confirms.
- **False positive when:** a client retries with an expired token. Fix the client, then unlock and unblock.

### SEN-002 SQL injection attempt (T1190, high)

- **Fires when** a request carries SQL injection patterns.
- **Platform already does:** blocks the source for 1800 s, creates an incident, notifies.
- **Check:** the path and query in the event. If the target was the v1 shop, the attempt is expected lab traffic.
- **Contain further:** review whether the target responded with data (the shop's error pages are a known leak in v1).
- **False positive when:** a search term legitimately contains quotes or SQL keywords. Tune the rule threshold in YAML.

### SEN-003 Cross-site scripting attempt (T1190, medium)

- **Fires when** a request carries script-injection patterns.
- **Platform already does:** rate-limits the source to 20 requests a minute, creates an incident.
- **Check:** whether the payload reached a page that reflects it unencoded. In v1 it does (F-07).
- **False positive when:** a user pastes markup into a search box. Usually no action beyond the incident.

### SEN-004 Port scan (T1046, medium)

- **Fires when** one source touches many distinct destination ports within a short window.
- **Platform already does:** blocks the source for 3600 s, creates an incident, notifies.
- **Check:** whether the source is a scanner you run on purpose (the lab). Scanning a host you do not own is
  an incident to escalate, not a rule to tune away.
- **False positive when:** a monitoring system probes many ports on a schedule. Allow it by removing the source from
  the blocklist and recording why in the incident.

### SEN-005 Known scanner user-agent (T1595, low)

- **Fires when** a request carries a scanner's default user agent.
- **Platform already does:** rate-limits to 10 requests a minute, creates an incident.
- **Check:** whether the traffic is expected (a security tool on a schedule) or a surprise.
- **False positive when:** a vendor's crawler uses a default agent. Note it and leave the limit in place.

### SEN-006 Valid account used from a new country (T1078, medium)

- **Fires when** an account authenticates from a country it has not used before. The country comes from the event.
- **Platform already does:** creates an incident and notifies. It does not block or lock.
- **Check:** whether the user travelled. Contact the user through a known channel, not the address in the alert.
- **Contain further:** if the user did not travel, lock the account and reset its credentials.
- **False positive when:** the user is on a VPN or a mobile carrier with a different country. Add the carrier to the
  notes and close the incident.

### SEN-007 HTTP request flood (T1499, high)

- **Fires when** one source sends a flood of HTTP requests.
- **Platform already does:** blocks the source for 900 s, rate-limits it to 30 requests a minute, creates an incident,
  notifies.
- **Check:** whether the flood reached the target and caused errors. Check the gateway's 429 responses.
- **False positive when:** a load test runs from a known address. Remove the block for that address after the test.

### SEN-008 Credential stuffing (T1110.004, high)

- **Fires when** one source tries many distinct accounts with few attempts each.
- **Platform already does:** blocks the source for 7200 s, creates an incident, notifies.
- **Check:** how many accounts were tried and whether any login succeeded. A successful login after many failures
  is the case to escalate.
- **False positive when:** a password manager or SSO sync retries many accounts from one address.

### SEN-009 Path traversal attempt (T1190, medium)

- **Fires when** a request contains traversal sequences in a path or file parameter.
- **Platform already does:** rate-limits the source to 20 requests a minute, creates an incident.
- **Check:** whether the file endpoint returned content. In v1 `/api/files` does (F-12).
- **False positive when:** a legitimate path contains two dots. Tune the pattern.

### SEN-010 Suspicious process spawned by an office application (T1059, high, endpoint)

- **Fires when** Word, Excel or a similar application starts a script host or shell.
- **Platform already does:** locks the account of the user on the endpoint, creates an incident, notifies.
- **Check:** the parent and child process names and the command line in the incident. Confirm with the user before
  anything else; the lock is the first containment step, not the investigation.
- **Contain further:** isolate the endpoint through your endpoint tooling. Sentinel does not isolate hosts.
- **False positive when:** an approved macro runs a script. Record the approval and unlock the account.

### SEN-011 Encoded or obfuscated PowerShell (T1059.001, high, endpoint)

- **Fires when** PowerShell runs an encoded or heavily obfuscated command.
- **Platform already does:** locks the account, creates an incident, notifies.
- **Check:** decode the command in a sandbox, not on the endpoint. Look for download cradles and credential access.
- **False positive when:** an installer uses encoded commands. Confirm the installer and unlock.

### SEN-012 Service installed from a user-writable location (T1543, high, endpoint)

- **Fires when** a new Windows service points at a user-writable path.
- **Platform already does:** creates an incident and notifies. It does not lock.
- **Check:** the service binary, its signature and its install time. Remove the service only after you have a copy of
  the binary for the investigation.
- **False positive when:** a per-user application installs a service from its own folder. Record and close.

### SEN-013 Network-layer connection flood (T1499, high, network)

- **Fires when** one source opens a large number of connections on the network sensor's flow records.
- **Platform already does:** blocks the source for 900 s, creates an incident, notifies.
- **Check:** whether the flows are real connections or a scan (SEN-004 usually fires alongside).
- **False positive when:** a load balancer or NAT concentrates many clients behind one address. Add that address to the
  notes and remove the block.

## ML detectors

### Network IDS (XGBoost, binary and multi-class)

- **Fires as** a detection with the model name and the predicted class.
- **Check:** the class and confidence in the explanation. The model was trained on CIC-IDS2017; treat it as one more
  signal and read the flow features before acting.

### Phishing URL classifier (opt-in)

- **Enabled by** `PHISHING_DETECTOR_ENABLED=1`. It is off by default because it flags legitimate URLs with a trailing
  slash (see the model card). Do not enable it on real traffic until that is fixed.
- **If enabled and it fires:** verify the URL in a sandbox, never by visiting it, and check the sender.

### Card-fraud model

- **Fires on** `transaction` events only. The generator does not yet produce them, so this path is exercised by
  published events.
- **Check:** the score and the transaction amount. Confirm with the cardholder through the bank's channel.

### Anomaly models

- **Not live.** The Isolation Forest and autoencoder are trained and evaluated, but no detector runs them yet.

## Triage agent

- Run it against a stored incident: `python -m sentinel.triage.run --incident-id <id>`.
- The report is a suggestion. It cannot block, lock or change anything, and its severity is pinned to the detector's.
- If the provider is unavailable or the reply does not match the schema, the report falls back to a fixed summary and
  says so in `source` and `reason`. Read the fallback as "no analysis happened", not as a verdict.
