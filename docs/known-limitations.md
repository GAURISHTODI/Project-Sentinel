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
