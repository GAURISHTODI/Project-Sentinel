# WinPulse — Windows endpoint log format (T11)

WinPulse is Sentinel's name for the normalized-at-the-source JSON shape its Windows endpoint exporter
emits, one line per event, built directly from native Windows Event Log channels (no Sysmon or other
third-party driver required):

| WinPulse `event_type` | Real Windows source | Event ID |
|---|---|---|
| `process_create` | Security log, "Audit Process Creation" | 4688 |
| `service_install` | System log (audited by default, no config needed) | 7045 |
| `powershell_script_block` | `Microsoft-Windows-PowerShell/Operational` | 4104 |

## Envelope
```json
{
  "winpulse_version": "1.0",
  "ts": 1790900000.123,
  "host": "WORKSTATION-07",
  "channel": "Security",
  "event_id": 4688,
  "event_type": "process_create",
  "data": { "...": "event-id-specific fields, see below" }
}
```

`data` fields per `event_type` (named after the real Windows EventData fields so a genuine Windows
Event Log export maps onto this with no semantic translation):

- **process_create (4688):** `NewProcessName`, `CommandLine`, `ParentProcessName`, `SubjectUserName`,
  `SubjectDomainName`.
- **service_install (7045):** `ServiceName`, `ImagePath`, `ServiceType`, `StartType`, `AccountName`.
- **powershell_script_block (4104):** `ScriptBlockText`, `ScriptBlockId`, `Path`, `UserId`.

## Exporter
`windows/winpulse_exporter.py` reads these three channels from the real local Windows Event Log (via
`pywin32`) and publishes WinPulse JSON to Kafka topic `logs.endpoint`. It is read-only and enables no
audit policy itself:

- **Service installs (7045)** are audited by Windows by default, so this works immediately on any
  Windows machine with no configuration.
- **Process creation (4688)** needs "Audit Process Creation" enabled (Local/Group Policy,
  `auditpol /set /subcategory:"Process Creation" /success:enable`) and, for a real command line to be
  captured, the `IncludeCmdLine` registry value — both require administrator rights to turn on. The
  exporter detects whether the channel/event ID is actually producing events and reports which channels
  were live in its summary; it never fabricates data for a channel that is not configured.
- **PowerShell Script Block Logging (4104)** similarly needs Script Block Logging enabled.

On a default, unconfigured developer machine, only service-install events will be real; process-creation
and PowerShell events are demonstrated by `windows/samples/*.json` instead. This mirrors the project's
documented fallback pattern elsewhere (e.g. T12's tshark-derived-flows fallback when Zeek is unavailable).

## Sample logs
`windows/samples/*.json` are hand-written, one JSON object per line, matching the exact envelope and
`data` shape a real Windows Event Log export would produce for each of the three event types, in both a
benign and an attack-scenario form, used as test fixtures for the normalizer and rules SEN-010..012.

## Usage
```bash
python -m sentinel.ingest.normalize_endpoint --from-beginning   # consume logs.endpoint -> events.normalized
python windows/winpulse_exporter.py --once                      # one real export pass, prints a summary
```
