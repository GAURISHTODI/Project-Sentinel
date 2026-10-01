# Known limitations (running list, kept honest as the build proceeds)

## Rules (T3)
- **SEN-006 baseline poisoning.** A "new country" rule needs a baseline of earlier logins. If an attacker
  takes over an account before any baseline exists, the attacker's logins become the baseline, and the real
  user's next normal login is then flagged as new. Observed in tests on takeover victims only.
- **SEN-006 cold start.** With no baseline (fewer than `min_baseline` earlier successful logins) a takeover
  cannot be detected. In the 40 s test run, 7 of 10 takeover campaigns hit users with no baseline yet.
- **SEN-007 threshold is absolute (150 requests / 10 s per IP).** It sits above the busiest benign source in
  the synthetic data (a shared NAT address, about 12 requests/s at 1,000 eps). A flood slower than
  15 requests/s from one IP is not detected, and a real NAT busier than the synthetic one would false-alarm.
- Thresholds were chosen from benign peaks in synthetic data, not from real traffic, and must be re-tuned
  on production telemetry.

## Generator (T2)
- Synthetic traffic is simpler than production: attackers use documentation IP ranges, stable per-user
  home IPs, and a handful of fixed payload families. Detection rates on it are not real-world rates.

## Network ML (T4)
- **Scores look near-perfect, and that is a property of the dataset.** CIC-IDS2017 attacks come from a few
  scripted tools, so flows within a class are near-identical. A random train/test split puts siblings of
  every test flow in the training set, which overstates how well the model generalises to new traffic.
  A split by day or by attack tool would give lower, more honest numbers (not yet done).
- **Sample is 196,514 rows, not 200,000.** Duplicates are removed before sampling (256,429 of 2.83M rows were
  duplicates), and some classes have fewer unique flows than their proportional target.
- **Rare classes are unreliable.** Infiltration has 7 test rows, Web Attack Brute Force 21 and XSS 20, and
  their F1 (0.83 / 0.50 / 0.61) swings with a handful of rows. SQL Injection (17 training rows) and
  Heartbleed (9) are too small to train a multi-class model on and are reported as not trained.
- **Per-class floor.** At least 100 rows (or all) of each class are kept, which very slightly over-represents
  the rarest classes compared with their true share.
- **Destination Port is a feature** and can act as a shortcut for attacks aimed at one port. No ablation yet.
- **The generator's synthetic flows use different feature names** from CIC-IDS2017, so the ML models cannot
  score them. Evaluation of the ML models uses the held-out CIC test split only.

## Detection engine and response (T5)
- **Windows are partition-local with write-behind to Redis.** A Redis round trip costs about 1 ms through
  Docker Desktop on Windows, which capped rules at roughly 1,200 events/s and left a live backlog (mean
  time-to-detect 15 s). Window state now lives in the consumer process and is mirrored to Redis in batches.
  This is exact only because Kafka keys events by source IP (one consumer sees every event of an IP). After a
  restart the windows start empty (up to one window of history is lost); Redis is not read back.
  Scaling to several consumers works for per-IP rules but a rule grouped by something other than the key
  (for example per user) would need a shared store.
- **Repeat suppression.** Repeat detections of an already-handled incident are counted in memory for 30 s and
  written to Postgres in batches, so a repeat does not re-run actions. A block lifted by an analyst can
  therefore be re-applied up to 30 s late.
- **Dry-run still records incidents** (that is how a policy is judged before enforcement) but never touches
  Redis keys, locks or the webhook.
- **Protected addresses are a short default list** (loopback, link-local). A real deployment must add its
  gateways, load balancers and shared NAT/VPN egress, or a noisy shared address could be blocked.
- **ML detector sees no synthetic flows.** Generator flows lack the CIC feature set, so the network model only
  fires on CIC-style flows (used in evaluation), not on generated traffic.
- Latency numbers quoted during development came from single informal runs; the official figures are produced
  by `python -m sentinel.eval.evaluate` (T6).

## API and evaluation (T6)
- **Evaluation scenarios are small samples.** A 60 s run at 1,000 events/s contains few campaigns of the
  slow, large scenarios (1 DoS, 2 port-scan and 5 credential-stuffing campaigns), so a recall of 1.00 there is
  weak evidence. The per-scenario table always shows the campaign counts for this reason.
- **Endpoint scenarios count as "no rule yet"** until T11; overall campaign recall is computed over the
  covered scenarios only and the uncovered ones are listed next to it.
- **"Time to detect" includes rule accumulation time.** It runs from the first event of a campaign to the first
  alert, so a threshold rule (for example 150 requests in 10 s) cannot beat its own threshold. The pipeline's
  own speed is reported separately as latency per detection.
- **Latencies come from one machine** where the generator, Kafka, Redis, Postgres and the service share
  16 GB and one CPU. They say nothing about a distributed deployment.
- **API:** tokens cannot be revoked individually before they expire (disabling or demoting the user does take
  effect on the next request); login throttling is per source IP and per username and keys off the socket
  address, so behind a proxy it would need a trusted forwarded-for setting; the API speaks plain HTTP until
  TLS is added in T21.

## target-shop and log ingestion (T7)
- **v1 is vulnerable on purpose.** Its flaws are the point; it must never leave the isolated lab network.
  The compose file gives it no host port and no internet route (`lab` and `backend` are internal networks).
- **No GeoIP for real logs.** The shop's logs carry no country, so SEN-006 (new-country login) cannot fire on
  real shop traffic; it only fires on generated events that include a country.
- **The access log has no authenticated user.** The shop does not resolve the session token per request, so
  access events carry no username; login events do.
- **Health-check traffic is logged.** The container health check requests `/api/health` every 10 s from
  localhost, so the log is never completely idle (and localhost is a protected address, never blocked).
- **Direct attacks bypass nothing yet:** until the gateway (T8) exists, nothing enforces Sentinel's blocks in
  front of the shop; blocks are recorded in Redis only.

## Responder gateway (T8)
- **Fixed one-minute window.** The rate limiter counts requests per calendar minute, so a client can send up
  to twice the limit across a minute boundary. Fine for coarse abuse control, not for precise quotas.
- **Dynamic limits can only tighten.** A Sentinel `sen:ratelimit:<ip>` value above the gateway default is
  ignored, so a corrupt or malicious Redis value can never loosen the limit.
- **Fail-open by default.** If Redis is unreachable the gateway keeps serving (counted in `storeErrors`)
  so a Redis outage is not a site outage; `GATEWAY_FAIL_OPEN=false` switches to answering 503.
- **Client address.** The gateway trusts only the TCP peer address and discards client-supplied
  X-Forwarded-For. Behind another proxy or cloud load balancer that address would be the proxy's, so a trusted
  forwarded-header setting would be needed first.
- **Two credentials on admin routes.** `/admin/**` needs a Sentinel JWT in `X-Sentinel-Token` (checked at the
  gateway) in addition to the shop's own session token (checked by the shop).
- **JWT roles are not re-checked at the gateway.** A token carries its role until it expires (30 minutes by
  default); the Python API re-reads roles per request, the gateway cannot without a database lookup.
- **Plain HTTP between gateway and shop** until TLS arrives in T21; both are on an internal network.

## Attack lab (T9)
- **SEN-004 (port scan) does not fire on real Nmap traffic against target-shop.** The shop exposes exactly
  one TCP port; a full port scan's probes against the other 65,534 ports are rejected at the kernel/TCP
  layer and never reach any component Sentinel can observe. Only Nmap's HTTP-layer NSE scripts (service/
  title detection) are visible, and those correctly trip SEN-005 (scanner user-agent). Real network-level
  port-scan detection needs packet capture, which is T12's job.
- **Hydra needs the `1=` http-post-form option.** target-shop returns a genuine HTTP 401 for bad credentials
  (correct REST behaviour), but Hydra's default heuristic treats any 401 as "this is HTTP Basic Auth, not a
  form" and refuses to process attempts, silently retrying forever instead of counting them as failures.
  `lab/03_hydra.sh` passes `1=` to tell Hydra to treat 401 as a normal form failure.
- **A source that gets blocklisted stays blocked for later, unrelated attacks from the same IP.** This is
  correct behaviour (the whole point of the blocklist), but it means a later lab script run from a
  previously-flagged attack container will be refused at the gateway (403) before it can demonstrate its own
  specific detection. Clear `sen:blocklist:<ip>` in Redis between isolated single-technique demonstrations.
- **The `lab` network has no internet egress once a tool container joins it** (`internal: true`). Tool images
  must be pulled or built before they are run with `--network lab`; ZAP in particular never reaches its own
  update servers at scan time and runs entirely on its image's bundled rule set.
- **ZAP's active scan (`zap-full-scan.py`) independently rediscovered real SQLi and XSS** using its own
  payloads (not reused from our test suite), and that traffic correctly tripped SEN-002, SEN-003, SEN-007 and
  SEN-009 live through the real pipeline — useful independent corroboration for the OWASP findings in T10.
