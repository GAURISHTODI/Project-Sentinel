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

## Windows endpoint source (T11)
- **Real exporter verified on this actual dev machine**, not only against synthetic data:
  `windows/winpulse_exporter.py` is read-only (it enables no audit policy itself) and was run for real
  against three native Windows Event Log channels:
  - **Service installs (Event ID 7045, System log)** are audited by Windows by default on every machine;
    the exporter found 7 genuine real events (covering real services such as the Intel wireless driver and
    the Windows Subsystem for Linux install made earlier in this project).
  - **PowerShell script blocks (Event ID 4104)** were also real and present (156 events) even with no
    explicit Script Block Logging policy configured, since PowerShell 5.1+ logs its own built-in modules'
    internals unconditionally; all sampled content was benign Microsoft module-loading code.
  - **Process creation (Event ID 4688, Security log)** returned "Access is denied" when read without
    elevation — the Security log is the most access-restricted Windows log by design, separately from
    whether "Audit Process Creation" is even enabled. The exporter honestly reports 0 events and the access
    error rather than silently hiding the gap or fabricating data; it was deliberately not run elevated
    (enabling audit policy or granting log-read rights is a persistent, system-wide change on someone's own
    machine that was not asked for).
- **SEN-011's encoded-PowerShell detection is a precise pattern match only, not an entropy threshold.**
  An entropy-based branch (`cmdline_entropy|gt: 4.5`) was tried and then deliberately dropped after testing
  showed only a 0.33-bit margin between a real encoded payload (4.64) and ordinary admin PowerShell one-liners
  (4.32-4.41) — full-command-line entropy is diluted by the surrounding low-entropy English flags/prose, so
  it does not reliably separate the two. `cmdline_entropy` is still computed and exposed as a fact any rule
  can use (and is unit-tested), but no shipped rule currently keys off it alone for this reason.
- **SEN-011 does not catch a plain-text (unencoded) download-cradle script block**, e.g. a literal
  `IEX (New-Object Net.WebClient).DownloadString(...)` with no `-EncodedCommand`/`-enc` present. This matches
  the PRD's specific ask ("encoded PowerShell"), not broader PowerShell threat coverage; a plain-text
  suspicious-content rule would be a reasonable future addition, not claimed here.
- **F-09's class of gap, generalised:** endpoint detections (SEN-010/011/012) do not use `block_ip` directly
  in their own response lists, since blocking a compromised endpoint's own IP is not obviously the right
  first action (unlike blocking an external network attacker). The existing cross-rule escalation mechanism
  (3+ distinct detectors from one source in a window) can still add a block on top, which is realistic
  (network-isolating a confirmed-compromised workstation is a legitimate SOC action) but is a different,
  coarser decision than any single endpoint rule makes alone.
- **No real-world Sysmon integration.** WinPulse's three event types were chosen specifically because they
  need no Sysmon or other kernel driver, only native Windows Event Log channels; a Sysmon-based exporter
  (more event types, richer fields) is future scope, not attempted here.

## Network capture (T12)
- **Docker Desktop's WSL2-virtualised networking required two real workarounds**, found by actually
  capturing traffic rather than assuming a standard Linux Docker bridge would behave identically:
  1. `tshark`'s own live-capture wrapper fails to enumerate any interface inside a minimal container even
     though its underlying engine, `dumpcap`, works correctly when invoked directly. `dumpcap` is used for
     the capture step; `tshark` is still used unmodified to read and analyse the resulting pcap.
  2. A third-party container attached only to the `lab` network does not get true promiscuous visibility of
     *other* containers' traffic under Docker Desktop's WSL2 backend -- only its own traffic and broadcast
     noise (ARP, IPv6 neighbor discovery). The capture container instead shares the target's own network
     namespace (`--network container:sentinel-target-shop-1`), the standard "sidecar capture" pattern, which
     sees that container's real traffic directly with no change to the target image.
  3. A BPF capture filter (`-f "ip host ..."`) combined with the `any` pseudo-interface silently captured
     zero packets in this libpcap build (the filter does not match the SLL/cooked-mode framing `any`
     produces); the capture is therefore unfiltered and the documented filters are applied as tshark
     **display** filters when reading the pcap back instead -- the standard Wireshark workflow of capturing
     broadly then narrowing for analysis, not a step back from filtering.
- **A real, extreme-volume nmap scan (`-p-`, all 65,535 ports) exposed a genuine O(n^2) characteristic in
  `MemoryStore`'s sliding window** (`detect/rules/state.py`): `record()` scans its whole bucket on every
  call to evict expired entries, which is fine for realistic traffic (the synthetic generator's own port-scan
  scenario never exceeds 250 ports per campaign) but degrades badly when ~65,000 connection attempts for one
  key land inside the same sub-second window, since eviction never triggers until entries age past the
  window and the bucket just keeps growing. The real-world consequence is bounded: `CachedStore`, used by
  the live production pipeline (`sentinel.detect.run`), uses a `MemoryStore` internally for its hot path and
  would inherit this same characteristic for this one pathological case. `RedisStore` is algorithmically
  O(log n) per call (sorted-set operations), but at this same extreme volume the per-event, per-rule network
  round trip dominates instead: a direct `RedisStore` run over all 65,578 real events did not finish within
  60 seconds against either fakeredis or a real local Redis, confirming round-trip count, not Redis's own
  complexity, is the limiting factor there. None of this affects normal operation -- it was only reachable by
  deliberately running an attack tool with no realistic constraint on its own traffic volume, and detection
  was proven correct on a real, much smaller (but equally real, equally pcap-derived) slice of the same
  capture: see `network/samples/real_nmap_scan.conn.log`. Fixing the extreme-volume case (e.g. a
  time-ordered deque instead of a scanned dict in `MemoryStore`) is noted as future work, not attempted here.
- **SEN-013 (network-layer connection flood) needed a real-data bug fix.** The first version of the
  Suricata-side normalizer treated any flow state other than `"established"` as scan-like, which is wrong:
  a normal, fully-completed HTTP request legitimately ends in Suricata's `"closed"` state (after
  `"established"`), not stuck in `"established"` forever. This was caught by running Suricata for real over
  a captured DoS-flood pcap, not by a unit test fixture (the fixtures only ever exercised `"new"` vs
  `"established"`); fixed to check specifically for `state == "new"` (a flow that never got a reply),
  matching the equivalent, already-correct logic on the Zeek side (`ZEEK_INCOMPLETE_STATES`).

## Splunk visibility (T13)
- **A read-only bind mount broke Splunk's first-boot provisioning.** The app bundle was first mounted
  `:ro`. Splunk's ansible-based entrypoint recursively `chown`s all of `/opt/splunk` to the `splunk` user on
  every boot; it cannot change ownership inside a read-only mount, so provisioning hung at the
  `change_splunk_directory_owner` task and the container stayed `unhealthy` with permission errors. The
  mount is now writable. Found by reading the container log, not by assumption.
- **The health check had a false positive in my own watcher.** A `grep healthy` loop matched `unhealthy`
  and reported success. Waits now match the exact `(healthy)` status.
- **`docker exec` runs as uid 999 `ansible`, not `splunk`.** Splunk CLI and `btool` calls need
  `docker exec -u splunk` or they fail with `Permission denied` on files that are actually correct.
- **Splunk's REST API is on 8089, which is not published by compose.** Verification runs inside the container
  via `docker exec -u splunk ... curl https://localhost:8089`. Port 8000 (splunkweb) also fails from the Windows
  host's curl with a schannel TLS error (`SEC_E_INVALID_TOKEN`) even though HEC on 8088 works; the forwarder
  itself uses httpx and is unaffected.
- **The "Blocked IPs" saved search returned 0 rows on the first run while Postgres had 476 applied blocks.**
  Splunk auto-extracts the JSON `detail` object as dotted fields (`detail.outcome`, `detail.detector`), so the
  original `spath input=detail | search outcome="applied"` matched nothing. Fixed to filter on
  `detail.outcome`. Verified afterward: 475 applied block events across 81 IPs, matching Postgres exactly.
- **Saved searches use a 24-hour window, and the generator's timestamps span more than that.** Over all time
  the index holds the complete data (4,437 detections, 754 incidents, 8,176 audit rows, all matching Postgres
  or the sent count), but the dashboard only shows the last 24 hours of event time. This is correct behaviour,
  not data loss, but a reviewer looking at the dashboard will see fewer rows than exist.
- **Failed HEC sends for incidents and audit rows were silently skipped.** The forwarder advanced its
  row cursor even when HEC rejected the event, so those rows never reached Splunk and nothing counted the
  loss. Fixed: the cursor now stops at the first failure and the row is retried on the next poll, covered by
  an integration test with a forced 503. Detections still have no retry: a failed detection send is counted
  as `hec_failed` and dropped, because Splunk is visibility only and never drives a decision.
- **The pipeline run during verification was memory-constrained.** On this 16 GB machine a `MemoryError` hit
  the generator while 6 orphaned Sentinel consumers from earlier background launches were still running. Those
  were stopped and each stage was rerun in the foreground.

## Metrics and Grafana (T14)
- **The `notify` action was reported as `failed` when no webhook was configured.** `Notifier` returns False
  when there is no URL, and the action mapped that to `Outcome.FAILED`, so an unconfigured deployment
  reported every notification as a delivery failure. This showed up as 191 `notify=failed` series in the
  first live metrics scrape. Fixed with a distinct `not_configured` outcome, covered by a test. Existing audit
  rows from before the fix (`notify|failed`, 2,907 of them) were written for the same unconfigured state and
  are not real delivery failures.
- **The metrics endpoint listens on all interfaces (`0.0.0.0:8001`).** Prometheus runs in a container and
  reaches the host through `host.docker.internal`, which a loopback bind cannot serve. The endpoint is
  unauthenticated, so anyone who can reach that port on this machine's network can read the counters.
  Acceptable for a laptop lab; it should be bound to a private interface or put behind the gateway before any
  shared deployment.
- **Only the detection service is scraped.** The responder gateway, target-shop and the ingest normalizer
  export nothing. Gateway-level latency and rate-limit counts therefore do not appear in Grafana yet.
- **Latency histograms measure in-process work only.** `sentinel_event_processing_seconds` times rule and ML
  evaluation for one event. It does not include Kafka queueing time, so it understates end-to-end latency
  under load. `sentinel_response_seconds` times the action plan for one detection.
- **Counters reset when the process restarts.** Prometheus `rate()` handles resets, but `increase()` over a
  window that spans a restart undercounts by the pre-restart total.
- **The dashboard was checked through the APIs, not in a browser.** Every panel query returns real series from
  Prometheus and Grafana loads the provisioned dashboard and datasource (health OK). Visual layout was not
  inspected in a browser in this run.

## Anomaly models (T15)
- **Both models are weak on most attack classes.** Isolation Forest reached 14.7% recall and ROC-AUC 0.80; the
  autoencoder reached 49.7% recall, ROC-AUC 0.89 and PR-AUC 0.72, both at about a 1% false-positive rate on
  the untouched test split. Per class, the autoencoder catches DoS Hulk (84%), DDoS (44%) and slowloris (43%),
  but detects PortScan at 0.3%, and misses bot, FTP-Patator, SSH-Patator and all three web-attack classes
  entirely. Anomaly detection here is a volumetric-traffic detector, not a general intrusion detector.
- **Statistically normal attacks are invisible to these models.** Brute force and web attacks send well-formed
  requests with ordinary sizes and rates, so benign-only training gives them no reason to score high. The
  supervised models (T4) are the right tool for those classes, and the comparison is not like-for-like.
- **Thresholds were fixed before looking at the test split.** They are the 99th percentile of benign
  validation scores (1% FPR). Nothing was tuned on test rows; the per-class numbers are reported as measured.
- **Rare classes have very few test rows.** Heartbleed scored 100% detection on about two test rows, which is
  not meaningful as a rate. The per-class figures for rows below about 100 test samples are noise.
- **One sample, one seed.** Results are from seed 42 on the 196,514-row stratified sample. No confidence
  intervals were computed, and the sample is slightly below the requested 200,000 because of per-class floors.
- **Not wired into live detection.** The models are trained and evaluated, but `detect.run` does not yet score
  events with them. Deploying them as a live detector would also need a score-to-severity policy, which is not
  defined yet.
- **A first training run failed with `MemoryError` while a full pytest run was executing in parallel.** The
  retry, run alone, completed with the same sample and seed. Heavy jobs were not run concurrently after that.

## Phishing URL classifier (T16)
- **The headline score does not hold up on a trivial change.** On the host-disjoint test split the deployed
  model reaches F1 0.990, ROC-AUC 0.997 and 0.4% FPR. But appending a single `/` to legitimate test URLs
  flags 91.8% of them as phishing (the full-feature model: 100%). The dataset has no legitimate URL that ends
  in `/` and no legitimate URL with a path, so the model learned "bare domain means legitimate" through several
  features, not one. The test-split numbers are real but describe this dataset's construction, not live traffic.
- **Found on live URLs, not on the test set.** The first live run flagged `python.org`, `github.com` and
  `dkom.hr` as phishing at probability about 1.0. Inspecting the feature importances showed the full model relied
  on `path_len` (54%) and `has_https` (42%). A model without `path_len`, `has_https` and `has_www` was then
  deployed. That choice was made after observing the failure, not from test metrics, and it still fails the
  trailing-slash probe, so it is not a fix.
- **So the detector is opt-in.** It is registered only when `PHISHING_DETECTOR_ENABLED` is set. Enabling it
  will raise high-severity incidents on ordinary links, so it should not be enabled on real traffic until a
  dataset with legitimate URLs that have paths and query strings is available and the trailing-slash
  false-positive rate is acceptable.
- **Evaluation split is by host, so no domain appears on both sides.** Random splitting would have let the model
  memorise domains; that is why the host-disjoint split is used. Duplicate URLs (425) were dropped before
  splitting.
- **The dataset is a 2024 snapshot.** Phishing kits, naming habits and TLD use drift; nothing here was tested
  against recent phishing campaigns.
- **Only the URL string is used.** The dataset's page-content columns (title, favicon, line count, JS features)
  are excluded because they are unavailable for a URL seen in traffic. A richer model would need page fetching,
  which is out of scope and risky for untrusted links.

## Card-fraud model (T17)
- **The dataset came from a Hugging Face re-upload, not Kaggle.** Kaggle downloads need an account API key, and the
  OpenML mirror of the same ULB file kept resetting mid-transfer from this network (curl exit 56, and servers that
  ignored Range requests). The file used is `David-Egea/Creditcard-fraud-detection`. Its row count (284,807) and
  fraud count (492) and column layout match the published dataset, but its bytes were not checked against a
  published checksum, so treat the provenance as "matches the published counts", not "verified identical".
- **Features are anonymised PCA components.** V1..V28 cannot be explained in business terms, so an analyst sees a
  score, not a reason. The explanation field reports only the probability and amount.
- **Precision target missed slightly on test.** The threshold for 0.80 precision was chosen on validation rows and
  gave 0.794 precision on the untouched test split, with recall 0.867. The gap is expected from a threshold chosen
  on a smaller set; it is reported, not corrected by moving the threshold.
- **Imbalance is handled by class weights only.** `imbalanced-learn` is not installed, so SMOTE was not used.
  Class weights (`scale_pos_weight` from the fit split) avoid putting synthetic transactions into training.
- **Test set is small for the rarest class.** 98 frauds in the test split, so precision and recall at the high-precision
  targets rest on a few dozen detections. Per-target confidence intervals were not computed.
- **Two days, European cardholders, 2013.** Nothing here reflects current card-fraud patterns or other regions.
- **Time is relative, not wall-clock.** It is seconds from the first transaction in the dataset. Live transactions
  would need their own time reference, which the feature does not yet use.
- **No live source of transactions yet.** The traffic generator produces no `transaction` events, so the detector is
  exercised only by events published by hand. The live demo used five real rows (three frauds, two legitimate),
  all three frauds flagged and neither legitimate row flagged. That is a demonstration of the path, not a rate.

## LLM triage agent and injection suite (T18, T19)
- **The 100% injection pass rate is for scripted adversaries, not a real model.** The suite runs 19 textbook
  payloads in four untrusted fields (user agent, path, username, command line) against three fixed model
  behaviours: one that answers with a severity downgrade, one that requests an enforcement action, and one that
  echoes its input. All 228 cases pass. That shows the guardrails hold against those behaviours: schema
  validation, a fixed recommendation catalogue, severity pinned to the detector's value, and no executor in the
  agent. It does not show that a live language model resists injection. Measuring that needs a live model, which
  was not available here.
- **The live Gemini adapter has not been run.** There is no API key in this environment, so the adapter is covered
  only by a transport-mocked test of the request shape (key in a header, never in the URL). Its model name and
  endpoint should be confirmed against the current Gemini documentation before a live run.
- **Stored incidents do not keep raw event fields.** The incidents table holds the explanation, username and source
  IP. The user agent, path and command line that the injection suite exercises are not persisted, so triage of a
  stored incident sees less than the suite assumes. Passing those fields through would need a schema change.
- **The model may cite only techniques Sentinel maps.** Citations are checked against the ATT&CK ids in the rule files
  and the ML mappings. A well-formed but unknown id such as T9999 is rejected; that check was added after a test
  showed the first version accepted it.
- **Severity is pinned to the detector's value.** The model's severity is discarded and recorded as an override.
  That is deliberate: the model should not be able to move an incident's severity in either direction.
- **The call budget is in memory.** The daily cap resets when the process restarts, so a restart can exceed the
  intended daily limit. Persisting the counter is not done yet.
- **Triage output is a suggestion.** Recommendations such as `block_source_ip_after_review` are text for an analyst.
  Nothing in the agent calls the responder, so no enforcement follows from a model reply.

## CI security gates (T20)
- **Measured locally, before and after (results/ci/summary.json):** gitleaks 3 to 0; Semgrep 85 findings and a parse
  error to 0 and 0; Trivy HIGH and CRITICAL with a fix available, target-shop 38 to 0 and responder 35 to 0.
  Each suppression is listed with its reason. The Semgrep suppressions are five annotated sites and six ignored paths.
  Gitleaks has three allowlisted items.
- **Two gates have not been run locally.** OWASP Dependency-Check needs a long NVD download, and CodeQL runs only in
  GitHub's CI. Both are configured in `security.yml` but their counts are not measured.
- **The ZAP baseline on target-shop v2 is passive only.** It reported 61 pass, 0 new failures, 0 new warnings. The
  active scan in `lab/04_zap_baseline.sh` failed with a Docker container error (unexpected EOF) and now exits non-zero.
- **Scans of the first images were stale.** The Dockerfiles copy `target/*.jar`, and `mvn test` does not rebuild it.
  The Trivy results of the first pass describe the old jars. The workflow now packages the jars before the image job.
- **Several CI defects would have failed on the first run.** The Trivy action tag `0.28.0` does not exist (it is
  `v0.28.0`). The image job built images without packaging the jars. Checkov rejected the `docker_compose` framework.
  The DAST job scanned v1 where the spec requires v2. All were corrected.
- **Accepted Checkov findings.** HEALTHCHECK (CKV_DOCKER_2) and USER (CKV_DOCKER_3) are soft-failed. The tshark capture
  image runs as root with NET_RAW and NET_ADMIN granted at run time, and it is lab-only. Compose health checks cover the
  services that need them.
- **Trivy analysis needed a longer timeout.** The default five-minute limit was too short for the layers, so the
  scans used 40 minutes. Images were scanned from exported tarballs, because the Docker socket mount failed under Docker
  Desktop.
- **Spring Boot moved to 3.5.14, with pinned Spring, Jackson, Tomcat and Kafka versions.** Tomcat 10.1.58 is not on Maven
  Central, so 10.1.59 is pinned. Both suites pass. The 3.4 line had no fix for one finding, so the upgrade was needed.
- **Hydra lab image moved to a pinned Debian base.** `kalilinux/kali-rolling` only has a `latest` tag on Docker Hub. The
  image builds and runs, but the lab attack script was not rerun against it.
- **Action pins are SHAs.** The tags were resolved through the GitHub API at the time of writing. They will need
  updating when the actions are upgraded.

## Platform security (T21, partial)
- **Services connect as their own database role.** Detection uses `sentinel_detect`, the API and its user CLI use
  `sentinel_api`, and the Splunk forwarder and triage runner use `sentinel_reader`. The evaluation harness keeps the
  owner because it deletes rows between runs. Integration tests check what each role may and may not do, and an
  end-to-end detection run under `sentinel_detect` wrote 198 audit rows with no permission errors.
- **The audit log is append-only at the database layer.** A trigger rejects UPDATE and DELETE for every role,
  including the owner. A privileged user can disable the trigger, so the hash chain is the real tamper evidence. The
  tamper test disables the trigger explicitly to show the chain still catches an edit.
- **Passwords for the new roles are in the gitignored .env.** Docker secrets or Vault would be the right home, and
  neither is wired in yet.
- **No TLS between services yet.** There is no dev CA and no mTLS. Traffic between the API, the database, Kafka and
  Redis is plaintext on the internal Docker networks.
- **Security headers are tested on every response.** The API already sets nosniff, DENY framing, no-store caching,
  no referrer and a restrictive CSP. HSTS is not sent because the lab serves plain HTTP.
