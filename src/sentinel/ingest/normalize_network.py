"""Normalizer: Zeek conn.log / Suricata eve.json (flow records) -> NormalizedEvent.

Both formats describe the same thing (one network flow/connection) with different field names and
different timestamp conventions; both are mapped onto the same flow_features vocabulary the
generator already uses (duration, fwd_packets, bwd_packets, bytes, syn_count, pkts_per_sec), so
SEN-004/SEN-013 work identically on synthetic and real, pcap-derived traffic.

Input is a replayed pcap's derived log, which on a real network is attacker-influenced (a scanner
chooses its own ports, packet sizes and TCP flags) -- every field is validated and bounded; a line
that cannot become a valid event is counted and dropped, never raises.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from collections import Counter
from datetime import datetime
from typing import Any

from sentinel.common.config import get_settings
from sentinel.common.logging import get_logger
from sentinel.common.schema import NormalizedEvent

log = get_logger(__name__)
ZEEK_INCOMPLETE_STATES = {"S0", "S1", "S2", "S3", "REJ", "RSTOS0", "RSTRH"}


def _ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except (ValueError, TypeError):
        return None


def _port(value: Any) -> int | None:
    try:
        p = int(float(value))
    except (TypeError, ValueError):
        return None
    return p if 0 <= p <= 65535 else None


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# ------------------------------------------------------------------ Zeek conn.log (TSV)


def normalize_zeek_conn_line(line: str, fields: list[str]) -> NormalizedEvent | None:
    """One tab-separated conn.log data row (not a #-comment/header line) -> a flow event."""
    if not fields:
        return None
    values = line.rstrip("\n").split("\t")
    if len(values) != len(fields):
        return None
    row = dict(zip(fields, values, strict=True))

    src_ip = _ip(row.get("id.orig_h"))
    dst_ip = _ip(row.get("id.resp_h"))
    dst_port = _port(row.get("id.resp_p"))
    if src_ip is None or dst_ip is None:
        return None
    try:
        ts = float(row.get("ts", "-"))
    except ValueError:
        return None

    orig_pkts = _float(row.get("orig_pkts"))
    resp_pkts = _float(row.get("resp_pkts"))
    duration = _float(row.get("duration"))
    total_bytes = _float(row.get("orig_ip_bytes")) + _float(row.get("resp_ip_bytes"))
    state = row.get("conn_state", "")
    # a connection that never completed a handshake (no reply, reset, ...) looks like a scan probe
    syn_count = orig_pkts if state in ZEEK_INCOMPLETE_STATES else 1.0

    return NormalizedEvent(
        source="network",
        event_type="flow",
        timestamp_generated=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        flow_features={
            "duration": duration,
            "fwd_packets": orig_pkts,
            "bwd_packets": resp_pkts,
            "bytes": total_bytes,
            "syn_count": syn_count,
            "pkts_per_sec": (orig_pkts + resp_pkts) / max(duration, 1e-6),
        },
    )


def parse_zeek_fields(header_lines: list[str]) -> list[str]:
    """Pull the column names out of conn.log's '#fields\\t...' header line."""
    for line in header_lines:
        if line.startswith("#fields"):
            return line.rstrip("\n").split("\t")[1:]
    return []


def iter_zeek_conn(path: str) -> list[NormalizedEvent]:
    out: list[NormalizedEvent] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        header: list[str] = []
        fields: list[str] = []
        for line in f:
            if line.startswith("#"):
                header.append(line)
                if line.startswith("#fields"):
                    fields = parse_zeek_fields(header)
                continue
            ev = normalize_zeek_conn_line(line, fields)
            if ev is not None:
                out.append(ev)
    return out


# ------------------------------------------------------------------ Suricata eve.json (flows)


def _parse_suricata_ts(value: Any) -> float | None:
    """Suricata timestamps are ISO 8601 with a numeric UTC offset, e.g. '...+0000'."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except ValueError:
        return None


def normalize_suricata_line(line: str) -> NormalizedEvent | None:
    """One eve.json line; only event_type == 'flow' becomes an event (others are skipped)."""
    try:
        raw = json.loads(line)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(raw, dict) or raw.get("event_type") != "flow":
        return None

    src_ip = _ip(raw.get("src_ip"))
    dst_ip = _ip(raw.get("dest_ip"))
    dst_port = _port(raw.get("dest_port"))
    if src_ip is None or dst_ip is None:
        return None
    ts = _parse_suricata_ts(raw.get("timestamp"))
    if ts is None:
        return None

    flow_raw = raw.get("flow")
    flow: dict[str, Any] = flow_raw if isinstance(flow_raw, dict) else {}
    fwd = _float(flow.get("pkts_toserver"))
    bwd = _float(flow.get("pkts_toclient"))
    start, end = _parse_suricata_ts(flow.get("start")), _parse_suricata_ts(flow.get("end"))
    duration = max((end - start), 0.0) if start is not None and end is not None else 0.0
    total_bytes = _float(flow.get("bytes_toserver")) + _float(flow.get("bytes_toclient"))
    # Suricata flow states: new (handshake in progress, no reply yet) -> established -> closed
    # (properly torn down). Only "new" (never got a reply) looks like a scan probe; a flow that
    # reached "closed" completed a normal request/response cycle and is not scan-like.
    state = str(flow.get("state", ""))
    syn_count = fwd if state == "new" else 1.0

    return NormalizedEvent(
        source="network",
        event_type="flow",
        timestamp_generated=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        flow_features={
            "duration": duration,
            "fwd_packets": fwd,
            "bwd_packets": bwd,
            "bytes": total_bytes,
            "syn_count": syn_count,
            "pkts_per_sec": (fwd + bwd) / max(duration, 1e-6),
        },
    )


def iter_suricata_eve(path: str) -> list[NormalizedEvent]:
    out: list[NormalizedEvent] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            ev = normalize_suricata_line(line)
            if ev is not None:
                out.append(ev)
    return out


# ------------------------------------------------------------------ CLI: replay a file to Kafka


def main(argv: list[str] | None = None) -> int:
    from sentinel.ingest.producer import EventProducer

    ap = argparse.ArgumentParser(
        description="Replay a Zeek conn.log or Suricata eve.json to events.normalized"
    )
    ap.add_argument("path")
    ap.add_argument("--format", choices=["zeek", "suricata"], required=True)
    a = ap.parse_args(argv)

    events = iter_zeek_conn(a.path) if a.format == "zeek" else iter_suricata_eve(a.path)
    cfg = get_settings()
    out = EventProducer(cfg.kafka_bootstrap, cfg.events_topic)
    counts: Counter[str] = Counter()
    for ev in events:
        out.send(ev)
        counts["normalized"] += 1
    out.flush()
    print(dict(counts), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
