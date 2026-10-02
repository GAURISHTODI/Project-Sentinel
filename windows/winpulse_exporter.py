"""Real Windows endpoint log exporter -> WinPulse JSON -> Kafka topic `logs.endpoint`.

Reads three native Windows Event Log channels, no Sysmon or other third-party driver required:
  - Security, Event ID 4688 (process creation) -- needs "Audit Process Creation" enabled
  - System, Event ID 7045 (service installed) -- audited by Windows by default, no config needed
  - Microsoft-Windows-PowerShell/Operational, Event ID 4104 (script block logging) -- needs
    PowerShell Script Block Logging enabled

This script is read-only: it never changes an audit policy itself. If a channel/event ID is not
configured on this machine it legitimately returns zero events for that type; this is reported in
the summary rather than silently hidden or faked. See windows/README.md.

Usage:
    python windows/winpulse_exporter.py --once [--minutes 60]   # one pass, print a summary, exit
    python windows/winpulse_exporter.py                          # keep polling and publish to Kafka
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

CHANNELS: list[tuple[str, int, str]] = [
    ("Security", 4688, "process_create"),
    ("System", 7045, "service_install"),
    ("Microsoft-Windows-PowerShell/Operational", 4104, "powershell_script_block"),
]


def _event_data(xml_text: str) -> dict[str, str]:
    """Pull EventData/Data name="..." values out of the event's rendered XML, skipping anything
    that fails to parse (malformed XML from the log is untrusted input, not a reason to crash)."""
    import xml.etree.ElementTree as ET

    out: dict[str, str] = {}
    try:
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        root = ET.fromstring(xml_text)  # noqa: S314  # local Event Log XML, not untrusted network input
        for data in root.findall(".//e:EventData/e:Data", ns):
            name = data.get("Name")
            if name:
                out[name] = data.text or ""
    except ET.ParseError:
        pass
    return out


def read_channel(
    channel: str, event_id: int, since: datetime, max_events: int = 500
) -> Iterator[dict[str, Any]]:
    """Yield raw (timestamp, EventData dict) pairs for one channel/event id, oldest first."""
    import pywintypes
    import win32evtlog

    query = (
        f"*[System[(EventID={event_id}) and "
        f"TimeCreated[@SystemTime>='{since.strftime('%Y-%m-%dT%H:%M:%S.000Z')}']]]"
    )
    try:
        handle = win32evtlog.EvtQuery(
            channel, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection, query
        )
    except pywintypes.error as exc:
        print(f"  [{channel}] could not open channel: {exc}", file=sys.stderr)
        return
    seen = 0
    while seen < max_events:
        events = win32evtlog.EvtNext(handle, 50, 1000)
        if not events:
            break
        for raw_event in events:
            xml_text = win32evtlog.EvtRender(raw_event, win32evtlog.EvtRenderEventXml)
            seen += 1
            yield {"ts": time.time(), "data": _event_data(xml_text)}
            if seen >= max_events:
                break


def to_winpulse(
    channel: str, event_id: int, event_type: str, host: str, record: dict[str, Any]
) -> dict[str, Any]:
    return {
        "winpulse_version": "1.0",
        "ts": record["ts"],
        "host": host,
        "channel": channel,
        "event_id": event_id,
        "event_type": event_type,
        "data": record["data"],
    }


def export_once(minutes: int) -> tuple[list[dict[str, Any]], Counter[str]]:
    """One real pass over all three channels. Returns (winpulse records, per-channel counts)."""
    import socket

    host = socket.gethostname()
    since = datetime.now(UTC) - timedelta(minutes=minutes)
    counts: Counter[str] = Counter()
    records: list[dict[str, Any]] = []
    for channel, event_id, event_type in CHANNELS:
        n = 0
        for record in read_channel(channel, event_id, since):
            records.append(to_winpulse(channel, event_id, event_type, host, record))
            n += 1
        counts[f"{channel} ({event_id})"] = n
    return records, counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Export real Windows endpoint logs to WinPulse/Kafka")
    ap.add_argument("--once", action="store_true", help="one pass, print a summary, do not publish")
    ap.add_argument("--minutes", type=int, default=60, help="look back this many minutes")
    ap.add_argument("--poll-seconds", type=float, default=15.0)
    a = ap.parse_args(argv)

    if a.once:
        records, counts = export_once(a.minutes)
        print(f"Looked back {a.minutes} minute(s) across {len(CHANNELS)} channels:")
        for name, n in counts.items():
            status = (
                "" if n else "  (0 events: channel likely not configured/audited on this machine)"
            )
            print(f"  {name:55s} {n:4d} events{status}")
        print(f"\ntotal WinPulse records that would be published: {len(records)}")
        for r in records[:3]:
            print("  example:", json.dumps(r)[:200])
        return 0

    from sentinel.common.config import get_settings
    from sentinel.ingest.producer import EventProducer

    cfg = get_settings()
    prod = EventProducer(cfg.kafka_bootstrap, "logs.endpoint")
    try:
        while True:
            records, _ = export_once(minutes=1)
            for r in records:
                prod.send_raw(json.dumps(r), key=str(r["host"]))
            if records:
                print(f"published {len(records)} WinPulse records", file=sys.stderr)
            time.sleep(a.poll_seconds)
    except KeyboardInterrupt:
        pass
    finally:
        prod.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
