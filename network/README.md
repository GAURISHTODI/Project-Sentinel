# Network capture (T12)

Real attack traffic is captured on the `lab` Docker network with `tshark`'s capture engine
(`dumpcap`), written to a pcap, then processed by both Zeek and Suricata to produce `conn.log` and
`eve.json`. `src/sentinel/ingest/normalize_network.py` turns either format into `NormalizedEvent`s
on the same `flow_features` vocabulary the generator's synthetic network events already use, so
SEN-004 (port scan) and SEN-013 (network-layer connection flood) fire identically on real,
pcap-derived traffic and on synthetic data.

## Running a real capture
```bash
cd lab
bash 06_capture_attack.sh ./01_nmap_scan.sh                                # port scan
bash 06_capture_attack.sh ./05_dos_flood.sh http://172.30.0.11:8080 400 20  # flood
```
This captures, then runs Zeek and Suricata automatically, and prints the paths to feed into the
normalizer (`python -m sentinel.ingest.normalize_network <path> --format zeek|suricata`). The full
pcap and Zeek/Suricata output directories are gitignored (regenerable, and the pcap alone can be
tens of MB for a full port scan); `samples/` below holds small, curated, genuinely real slices of
captures made this way, kept as committed evidence.

## Wireshark/tshark filters used
See the header of `lab/06_capture_attack.sh` for the exact list and the reason the capture itself
is unfiltered (a BPF filter did not match correctly against this setup's cooked-capture framing) --
filtering is applied as a **display** filter when reading the pcap back instead, which is the
standard Wireshark workflow of capturing broadly then narrowing down for analysis.

## samples/
| File | What it is |
|---|---|
| `sample.conn.log` | Hand-written Zeek conn.log fixture: 2 benign connections + a 16-port scan, used for normalizer unit tests |
| `sample.eve.json` | Hand-written Suricata eve.json fixture, including a non-flow (`alert`) line the normalizer must skip |
| `real_nmap_scan.conn.log` | A genuinely real slice: Zeek's own output from processing a pcap of an actual `nmap -p- -sV -sC` scan against the live `target-shop` container |
| `real_dos_flood.eve.json` | A genuinely real slice: Suricata's own output from processing a pcap of an actual `lab/05_dos_flood.sh` run against `target-shop` |

## Three real platform findings from getting capture working
Docker Desktop's WSL2-virtualised networking needed real debugging, not just configuration, to get
genuine packet capture working. See `docs/known-limitations.md` (Network capture, T12) for the full
account: tshark's own capture wrapper failing where `dumpcap` succeeds, a third-party container not
getting promiscuous visibility of other containers' traffic (fixed with network-namespace sharing),
and a capture filter silently dropping every packet on the `any` pseudo-interface.
