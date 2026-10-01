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
