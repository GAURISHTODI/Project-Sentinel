#!/usr/bin/env bash
# Captures real attack traffic on the `lab` Docker network with tshark, to a pcap file, then runs
# Zeek and Suricata over that pcap to produce conn.log / eve.json. T12.
#
# Wireshark/tshark filters used (documented per TASKS.md): the capture itself is unfiltered (see
# the "any interface" note below for why); filtering is applied as DISPLAY filters afterward, the
# standard Wireshark workflow of capturing broadly then narrowing down for analysis:
#   "ip.addr == 172.30.0.11"                              -- only traffic to/from the lab target
#   "tcp.flags.syn==1 and tcp.flags.ack==0"                -- bare SYNs (port-scan probes)
#   "tcp.analysis.retransmission"                          -- retransmits (flood/congestion signal)
#   "http.request"                                         -- HTTP requests, for the flood scenario
#
# Usage: lab/06_capture_attack.sh [attack_script] [attack_args...]
#   e.g. lab/06_capture_attack.sh ./01_nmap_scan.sh
#        lab/06_capture_attack.sh ./05_dos_flood.sh http://172.30.0.11:8080 400 20
set -euo pipefail
cd "$(dirname "$0")"
source ./guard.sh
export MSYS_NO_PATHCONV=1

OUT_DIR="../results/network"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%dT%H%M%S)"
PCAP="capture_${TS}.pcap"

docker build -q -t sentinel-lab/tshark ./tools/tshark >/dev/null

echo "[capture] starting capture on the lab network (unfiltered; see display filters above)"
# Two real findings from getting this working under Docker Desktop's WSL2-virtualized networking:
#  1. dumpcap (tshark's own capture engine) is used directly: tshark's live-capture wrapper fails
#     to enumerate interfaces in this minimal container even though dumpcap itself works correctly;
#     tshark is still used unmodified below to read and analyse the resulting pcap file.
#  2. capturing on the container's own named interface ("-i eth0") silently captures zero packets,
#     even with --privileged, even for traffic unambiguously sent to that exact container. The
#     Linux "any" pseudo-interface (cooked/SLL capture across all interfaces) works correctly and
#     is used instead; this is a known way around per-interface binding limits some virtualised
#     NIC drivers have.
#  3. a BPF capture filter ("-f") combined with "-i any" also silently drops every packet (the SLL
#     cooked-capture framing does not match a plain "ip host ..." filter in this libpcap build), so
#     the capture itself is unfiltered and filtering is applied as a tshark display filter instead.
#  4. Docker Desktop's WSL2-virtualised network does not give a third-party container true
#     promiscuous visibility of *other* containers' inter-container traffic -- only its own traffic
#     and broadcast noise (ARP/IPv6 ND). The capture container therefore shares target-shop's own
#     network namespace (--network container:...), which sees that container's real traffic
#     directly; this is the standard "sidecar capture" pattern and needs no change to the target
#     image itself.
docker run -d --name "tshark-capture-${TS}" --network container:sentinel-target-shop-1 --privileged \
  --entrypoint dumpcap -v "$(pwd)/../results/network:/capture" sentinel-lab/tshark \
  -i any -w "/capture/${PCAP}" >/dev/null
sleep 2  # let the capture process attach before traffic starts

if [ "$#" -ge 1 ]; then
  echo "[capture] running attack: $*"
  require_lab_target "172.30.0.11"
  "$@"
else
  echo "[capture] no attack script given; capturing ambient lab traffic for 10s"
  sleep 10
fi

sleep 2  # drain any in-flight packets
docker stop "tshark-capture-${TS}" >/dev/null
docker rm "tshark-capture-${TS}" >/dev/null
echo "[capture] pcap written to results/network/${PCAP}"

echo "[capture] running Zeek over the pcap -> conn.log"
ZEEK_DIR="zeek_out_${TS}"
mkdir -p "../results/network/${ZEEK_DIR}"
docker run --rm -v "$(pwd)/../results/network:/pcap" -w "/pcap/${ZEEK_DIR}" zeek/zeek:latest \
  zeek -C -r "/pcap/${PCAP}" >/dev/null

echo "[capture] running Suricata over the pcap -> eve.json"
SURICATA_DIR="suricata_out_${TS}"
mkdir -p "../results/network/${SURICATA_DIR}"
docker run --rm -v "$(pwd)/../results/network:/pcap" jasonish/suricata:latest \
  suricata -r "/pcap/${PCAP}" -l "/pcap/${SURICATA_DIR}" >/dev/null 2>&1 || true

echo "[capture] done:"
echo "  pcap:       results/network/${PCAP}"
echo "  Zeek:       results/network/${ZEEK_DIR}/conn.log"
echo "  Suricata:   results/network/${SURICATA_DIR}/eve.json"
echo "Feed these to the normalizer: python -m sentinel.ingest.normalize_network <path> --format zeek|suricata"
