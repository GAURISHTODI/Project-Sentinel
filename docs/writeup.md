# Sentinel: writeup

## Summary

Sentinel is an end-to-end detection and response platform for an e-commerce environment. It ingests four
log sources, detects attacks with ATT&CK-mapped rules and machine-learning models, responds automatically
through a gateway, forwards its evidence to Splunk, and offers an LLM triage agent whose output is only a
suggestion. Every number here comes from `results/metrics.json` or a saved model result, written by the
evaluation harness on a clean commit.

## Methods

**Data.** A synthetic generator produces normalised events from application, authentication, endpoint and
network sources, with labelled attack campaigns. Real data is used where it exists: CIC-IDS2017 for the
network models, a UCI phishing URL dataset, the ULB card-fraud dataset (through a Hugging Face mirror whose counts
match the published set), and real pcaps captured from live lab attacks for the network rules.

**Pipeline evaluation.** The evaluation harness runs the generator through Kafka into the real detection service
and the responder, then compares the detections with the campaign labels. Detectors never see the label; the label
is stripped before any detector runs.

**Models.** Supervised network models use a stratified split and fit scalers on the training split only. The
anomaly models are fit on benign traffic only, with thresholds set on held-out benign rows for a 1% false-positive
rate. The phishing and fraud models use host-disjoint and stratified splits respectively, and their thresholds are
chosen on validation data, never on the test split.

**Lab.** Attack scripts run only against the internal lab network. Each script has a guard that refuses any other
target, and the scripts use textbook tools and payloads.

## Results

Pipeline run (clean commit, live services, 60,000 events, seed 42):

- Campaign recall over the covered scenarios: 0.975. Valid-account abuse is the weakest at 0.744 (32 of 43 campaigns).
- Benign events that raised an alert: 7 of 54,000 (false-positive rate 0.00013), all from SEN-006.
- Time to detect an attack, from its first event: median 192 ms, 95th percentile 566 ms.
- Throughput: about 1,017 events per second on the laptop, with no invalid messages dropped.

Network models (CIC-IDS2017, 196,514-row sample, 39,303 test rows):

- XGBoost binary: F1 0.997, ROC-AUC 1.000, false-positive rate 0.0008.
- Random forest binary: F1 0.995, false-positive rate 0.0007.
- XGBoost multi-class: macro-F1 0.890.

Anomaly models (benign-only training, threshold at 1% false positives):

- Autoencoder: recall 0.497, ROC-AUC 0.885, PR-AUC 0.721.
- Isolation Forest: recall 0.147, ROC-AUC 0.801.

Phishing URL classifier (PhiUSIIL, host-disjoint test split):

- Deployed model: F1 0.990, ROC-AUC 0.997. It flags 92% of legitimate test URLs once a trailing slash is
  added, so it is opt-in and not a production control.

Card fraud (ULB data, test split with 98 frauds):

- PR-AUC 0.872, ROC-AUC 0.973. At the threshold chosen for 0.80 validation precision: test precision 0.794,
  recall 0.867.

Injection suite (T19): 228 cases (19 payloads in four fields against three scripted model behaviours). All pass.
These are scripted adversaries, not a live model.

Security gates (T20, measured locally): gitleaks 3 to 0 findings; Semgrep 85 to 0; Trivy HIGH and CRITICAL with
fixes available, 38 to 0 on target-shop and 35 to 0 on the responder; ZAP passive baseline on target-shop v2 with no
new failures or warnings.

## Limitations

These are the main ones. The full list, with the reasons, is in `docs/known-limitations.md`.

- **The data is curated.** CIC-IDS2017, the phishing dataset and the card-fraud dataset are from specific
  environments and periods. Good scores on them are not evidence of good performance on live traffic.
- **The phishing model learned the dataset's construction.** Legitimate URLs in the training data are bare domains,
  so a trailing slash flips the decision. It is not deployed on real traffic.
- **Anomaly models are weak on most attacks.** They catch volumetric floods and miss brute force, bots and web
  attacks. They are not yet wired into live detection.
- **The lab's attacks are the lab's attacks.** The rules cover the techniques in their files. An adversary who
  stays within the thresholds, or uses a technique with no rule, is not detected.
- **Several security gates have not run.** Dependency-Check and CodeQL are configured but not run locally. The
  Terraform gate evaluated nothing, because Checkov has no checks for the providers used.
- **Security controls are partial.** Postgres and Redis use verified TLS; Kafka is plaintext on internal networks.
  Credentials are Docker secrets for the containers, but the host-side processes still read `.env`.
- **The audit chain was reset once.** Test fixtures had written unhashed rows, and the append-only trigger made that
  unfixable in place. The lab database was re-created with the owner's approval. This is recorded in the known
  limitations.
- **Kubernetes manifests are checked, not deployed.** No kind cluster was created in this environment.
- **Triage is a suggestion, not an autonomous agent.** The live LLM adapter has not been run against its API.

## AI in security: trends and what this project takes from them

Language models are being applied across security work: summarising alerts, mapping activity to ATT&CK, drafting
investigation notes, and reviewing code. The same capability is available to attackers, for example to write
phishing text, to vary payloads, or to probe a defender's own tooling. Two design choices in Sentinel follow from
this.

First, the model never acts. Its output is validated against a fixed schema, its recommendations come from a fixed
catalogue, and the severity it reports is pinned to the detector's. Prompt injection is a real risk when an agent
reads attacker-controlled text, so untrusted fields are delimited and the injection suite checks what happens when a
model follows injected instructions.

Second, the detectors are not language models. The rule engine and the classical models are deterministic and
testable, which makes it possible to measure their false-positive rates and explain each alert.

## Zero-day considerations

Rules and supervised models only recognise patterns they were built for. A new attack that does not match a rule and
does not look like the training data will not be flagged by them. The anomaly models are meant to cover that gap, but
the measurements above show they catch only a part of the attack space, and they are not yet live. So the honest
position is that Sentinel detects known techniques well in its lab, and only partially covers unknown ones. Closing
that gap needs labelled data from real environments, and it needs the anomaly models wired in and measured on real
traffic, which this project has not done.
