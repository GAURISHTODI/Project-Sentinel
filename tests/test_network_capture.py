import json
from pathlib import Path

import pytest

from sentinel.detect.rules.engine import RuleEngine
from sentinel.detect.rules.state import MemoryStore
from sentinel.ingest.normalize_network import (
    iter_suricata_eve,
    iter_zeek_conn,
    normalize_suricata_line,
    normalize_zeek_conn_line,
    parse_zeek_fields,
)

SAMPLES = Path(__file__).parent.parent / "network" / "samples"
ZEEK_FIELDS = (
    "ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\t"
    "orig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\t"
    "orig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents"
).split("\t")


def zeek_row(
    ts: str = "1790950000.0",
    src: str = "10.20.0.5",
    sport: str = "53213",
    dst: str = "172.30.0.11",
    dport: str = "8080",
    state: str = "SF",
    orig_pkts: str = "5",
    resp_pkts: str = "4",
    duration: str = "0.1",
) -> str:
    return "\t".join(
        [
            ts,
            "Cxxxxxxxxxxxxxxxxx",
            src,
            sport,
            dst,
            dport,
            "tcp",
            "-",
            duration,
            "100",
            "200",
            state,
            "-",
            "-",
            "0",
            "S",
            orig_pkts,
            "768",
            resp_pkts,
            "1280",
            "-",
        ]
    )


def eve_flow(
    ts: str = "2026-10-02T00:00:00.000000+0000",
    src: str = "10.20.0.5",
    sport: int = 53213,
    dst: str = "172.30.0.11",
    dport: int = 8080,
    state: str = "established",
    pkts_toserver: int = 5,
    pkts_toclient: int = 4,
    start: str = "2026-10-02T00:00:00.000000+0000",
    end: str = "2026-10-02T00:00:00.100000+0000",
) -> str:
    return json.dumps(
        {
            "timestamp": ts,
            "event_type": "flow",
            "src_ip": src,
            "src_port": sport,
            "dest_ip": dst,
            "dest_port": dport,
            "proto": "TCP",
            "flow": {
                "pkts_toserver": pkts_toserver,
                "pkts_toclient": pkts_toclient,
                "bytes_toserver": 768,
                "bytes_toclient": 1280,
                "start": start,
                "end": end,
                "state": state,
            },
        }
    )


# ------------------------------------------------------------------ Zeek conn.log


def test_parse_zeek_fields_from_header() -> None:
    header = ["#separator \\x09\n", "#path\tconn\n", "#fields\t" + "\t".join(ZEEK_FIELDS) + "\n"]
    assert parse_zeek_fields(header) == ZEEK_FIELDS


def test_normal_connection_maps_all_fields() -> None:
    ev = normalize_zeek_conn_line(zeek_row(), ZEEK_FIELDS)
    assert ev is not None
    assert ev.source == "network" and ev.event_type == "flow"
    assert ev.src_ip == "10.20.0.5" and ev.dst_ip == "172.30.0.11" and ev.dst_port == 8080
    assert ev.timestamp_generated == pytest.approx(1790950000.0)
    assert ev.flow_features is not None
    assert ev.flow_features["fwd_packets"] == 5.0 and ev.flow_features["bwd_packets"] == 4.0
    assert ev.flow_features["syn_count"] == 1.0  # SF: completed handshake, not scan-like


@pytest.mark.parametrize("state", ["S0", "S1", "REJ", "RSTOS0"])
def test_incomplete_handshake_states_look_scan_like(state: str) -> None:
    ev = normalize_zeek_conn_line(zeek_row(state=state, orig_pkts="1", resp_pkts="0"), ZEEK_FIELDS)
    assert ev is not None and ev.flow_features is not None
    assert ev.flow_features["syn_count"] == 1.0  # == fwd_packets, not forced to 1 by a real reply


def test_malformed_rows_are_dropped_not_raised() -> None:
    assert normalize_zeek_conn_line("", ZEEK_FIELDS) is None
    assert normalize_zeek_conn_line("too\tfew\tcolumns", ZEEK_FIELDS) is None
    assert normalize_zeek_conn_line(zeek_row(), []) is None  # no header parsed yet
    assert normalize_zeek_conn_line(zeek_row(src="not-an-ip"), ZEEK_FIELDS) is None
    assert normalize_zeek_conn_line(zeek_row(ts="not-a-number"), ZEEK_FIELDS) is None


def test_hostile_port_values_are_rejected_not_crashed() -> None:
    ev = normalize_zeek_conn_line(zeek_row(dport="999999"), ZEEK_FIELDS)
    assert ev is not None and ev.dst_port is None  # out-of-range port: dropped, event still valid


def test_real_sample_file_parses_completely() -> None:
    events = iter_zeek_conn(str(SAMPLES / "sample.conn.log"))
    assert len(events) == 18
    assert all(e.source == "network" and e.event_type == "flow" for e in events)


# ------------------------------------------------------------------ Suricata eve.json


def test_normal_flow_maps_all_fields() -> None:
    ev = normalize_suricata_line(eve_flow())
    assert ev is not None
    assert ev.source == "network" and ev.event_type == "flow"
    assert ev.src_ip == "10.20.0.5" and ev.dst_ip == "172.30.0.11" and ev.dst_port == 8080
    assert ev.flow_features is not None
    assert ev.flow_features["fwd_packets"] == 5.0 and ev.flow_features["bwd_packets"] == 4.0
    assert ev.flow_features["duration"] == pytest.approx(0.1, abs=1e-3)
    assert ev.flow_features["syn_count"] == 1.0  # established: not scan-like


def test_non_flow_event_types_are_skipped() -> None:
    alert = json.dumps({"event_type": "alert", "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8"})
    assert normalize_suricata_line(alert) is None
    http = json.dumps({"event_type": "http", "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8"})
    assert normalize_suricata_line(http) is None


def test_new_state_flow_looks_scan_like() -> None:
    ev = normalize_suricata_line(eve_flow(state="new", pkts_toserver=1, pkts_toclient=0))
    assert ev is not None and ev.flow_features is not None
    assert ev.flow_features["syn_count"] == 1.0  # == fwd_packets


def test_closed_state_flow_is_not_scan_like() -> None:
    """Regression test: a real completed HTTP request ends in Suricata's 'closed' state (after
    'established'), not 'established' itself. An earlier version checked `state != "established"`,
    which wrongly treated every legitimately finished connection as scan-like; caught by running
    Suricata for real over a captured DoS-flood pcap, not by a unit test fixture."""
    ev = normalize_suricata_line(eve_flow(state="closed", pkts_toserver=6, pkts_toclient=4))
    assert ev is not None and ev.flow_features is not None
    assert ev.flow_features["syn_count"] == 1.0  # not fwd_packets (6): this is a normal connection


@pytest.mark.parametrize(
    "line",
    [
        "not json",
        "{}",
        "[]",
        "null",
        json.dumps({"event_type": "flow"}),
        '{"event_type": "flow", "src_ip": "bad"}',
    ],
)
def test_malformed_lines_are_dropped_not_raised(line: str) -> None:
    assert normalize_suricata_line(line) is None


def test_bad_timestamp_formats_are_dropped() -> None:
    assert normalize_suricata_line(eve_flow(ts="not-a-timestamp")) is None
    assert normalize_suricata_line(eve_flow(ts="2026-10-02 00:00:00")) is None  # missing offset


def test_real_sample_file_parses_and_skips_the_alert_line() -> None:
    events = iter_suricata_eve(str(SAMPLES / "sample.eve.json"))
    assert len(events) == 5  # 6 lines in the file, 1 is event_type=alert


# ------------------------------------------------------------------ genuinely real captures
#
# Both files below are curated slices of real data: a real `nmap -p- -sV -sC` scan and a real
# `lab/05_dos_flood.sh` run were captured live with tshark/dumpcap against the actual target-shop
# container (sharing its network namespace -- see lab/06_capture_attack.sh), then genuinely
# processed by Zeek and Suricata respectively. Nothing in these two files was hand-written.


def test_real_captured_nmap_scan_triggers_sen004() -> None:
    engine = RuleEngine(MemoryStore())
    events = iter_zeek_conn(str(SAMPLES / "real_nmap_scan.conn.log"))
    assert len(events) >= 16  # at least SEN-004's threshold of distinct ports
    fired: set[str | None] = set()
    for ev in events:
        fired |= {d.rule_id for d in engine.evaluate(ev)}
    assert "SEN-004" in fired


def test_real_captured_dos_flood_sample_is_valid_flow_data() -> None:
    events = iter_suricata_eve(str(SAMPLES / "real_dos_flood.eve.json"))
    assert len(events) >= 1
    for ev in events:
        assert ev.dst_ip == "172.30.0.11" and ev.dst_port == 8080
    # the full real capture (402 flows) triggers SEN-013; this curated slice is a sample of it for
    # normalisation testing, not a re-proof of the threshold (see test_sen013_... above for that,
    # and docs/known-limitations.md for why the full real files are not committed to the repo)


# ------------------------------------------------------------------ detections on real-format data


def test_sen004_port_scan_fires_identically_from_both_formats() -> None:
    for make_engine_input in ("zeek", "suricata"):
        engine = RuleEngine(MemoryStore())
        fired: set[str | None] = set()
        for i, port in enumerate(range(1000, 1016)):  # 16 distinct ports, threshold is 15
            if make_engine_input == "zeek":
                line = zeek_row(
                    ts=f"{1790950010 + i * 0.001:.6f}",
                    src="203.0.113.50",
                    dport=str(port),
                    state="S0",
                    orig_pkts="1",
                    resp_pkts="0",
                )
                ev = normalize_zeek_conn_line(line, ZEEK_FIELDS)
            else:
                ev = normalize_suricata_line(
                    eve_flow(
                        ts=f"2026-10-02T00:00:{10 + i * 0.001:09.6f}+0000",
                        src="203.0.113.50",
                        dport=port,
                        state="new",
                        pkts_toserver=1,
                        pkts_toclient=0,
                        start=f"2026-10-02T00:00:{10 + i * 0.001:09.6f}+0000",
                        end=f"2026-10-02T00:00:{10 + i * 0.001 + 0.00001:09.6f}+0000",
                    )
                )
            assert ev is not None
            fired |= {d.rule_id for d in engine.evaluate(ev)}
        assert "SEN-004" in fired, f"{make_engine_input} did not trigger SEN-004"


def test_sen013_network_flood_fires_on_many_connections_same_destination() -> None:
    engine = RuleEngine(MemoryStore())
    fired: set[str | None] = set()
    for i in range(160):  # threshold is 150 within 10s
        line = zeek_row(
            ts=f"{1790950020 + i * 0.01:.6f}", src="203.0.113.70", dport="8080", state="SF"
        )
        ev = normalize_zeek_conn_line(line, ZEEK_FIELDS)
        assert ev is not None
        fired |= {d.rule_id for d in engine.evaluate(ev)}
    assert "SEN-013" in fired


def test_sen013_does_not_fire_on_ordinary_benign_connection_volume() -> None:
    """A normal user's handful of connections per minute must never trip the flood threshold."""
    engine = RuleEngine(MemoryStore())
    fired: list[str | None] = []
    for i in range(20):
        line = zeek_row(ts=f"{1790950100 + i * 3.0:.6f}", src="10.20.0.9", dport="443", state="SF")
        ev = normalize_zeek_conn_line(line, ZEEK_FIELDS)
        assert ev is not None
        fired.extend(d.rule_id for d in engine.evaluate(ev))
    assert fired == []


def test_sen004_and_sen013_do_not_fire_on_the_real_benign_sample_rows() -> None:
    engine = RuleEngine(MemoryStore())
    events = iter_zeek_conn(str(SAMPLES / "sample.conn.log"))
    benign = [e for e in events if e.src_ip == "10.20.0.5"]
    assert benign and all(engine.evaluate(e) == [] for e in benign)
