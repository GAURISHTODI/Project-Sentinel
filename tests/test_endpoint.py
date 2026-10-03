import json
from pathlib import Path

import pytest

from sentinel.common.schema import MAX_LEN
from sentinel.detect.endpoint_features import command_line_entropy
from sentinel.detect.rules.engine import RuleEngine
from sentinel.detect.rules.state import MemoryStore
from sentinel.ingest.normalize_endpoint import normalize_message, normalize_winpulse

SAMPLES = Path(__file__).parent.parent / "windows" / "samples"


def winpulse(
    event_id: int, event_type: str, data: dict[str, object], **kw: object
) -> dict[str, object]:
    base: dict[str, object] = {
        "winpulse_version": "1.0",
        "ts": 1790900000.0,
        "host": "WORKSTATION-07",
        "channel": "Security",
        "event_id": event_id,
        "event_type": event_type,
        "data": data,
    }
    base.update(kw)
    return base


# ------------------------------------------------------------------ entropy


def test_entropy_is_none_for_empty_or_missing() -> None:
    assert command_line_entropy(None) is None
    assert command_line_entropy("") is None


def test_entropy_zero_for_uniform_string() -> None:
    assert command_line_entropy("aaaaaaaa") == pytest.approx(0.0)


def test_entropy_increases_with_character_diversity() -> None:
    low = command_line_entropy("aaaaaaaaaaaaaaaab")
    high = command_line_entropy("a1B2c3D4e5F6g7H8i9")
    assert low is not None and high is not None and high > low


def test_entropy_bounded_input_length() -> None:
    huge = "A" * 50_000 + "b"  # must not hang or blow memory on hostile input
    e = command_line_entropy(huge)
    assert e is not None and e >= 0.0


def test_cmdline_entropy_is_available_as_a_rule_fact() -> None:
    """A rule can reference `cmdline_entropy` the same way it references any schema field."""
    from sentinel.common.schema import NormalizedEvent
    from sentinel.detect.rules.engine import build_facts

    ev = NormalizedEvent(source="endpoint", event_type="process_create", command_line="abc123XYZ")
    facts = build_facts(ev)
    assert "cmdline_entropy" in facts
    assert facts["cmdline_entropy"] == pytest.approx(command_line_entropy("abc123XYZ"))


def test_rare_parent_child_pair_uses_the_existing_novelty_mechanism() -> None:
    """Endpoint rarity needs no new state backend: (parent, child) reuses Store.novel()."""
    from sentinel.detect.rules.state import MemoryStore

    store = MemoryStore()
    explorer = "C:\\Windows\\explorer.exe"
    # baseline: explorer spawning three common, unremarkable children
    for child in ("chrome.exe", "notepad.exe", "outlook.exe"):
        assert store.novel(f"parent:{explorer}", child, min_baseline=3) is False
    # a fourth, never-seen child after the baseline is the "rare pair" signal
    assert store.novel(f"parent:{explorer}", "powershell.exe", min_baseline=3) is True
    # seeing it again is no longer novel
    assert store.novel(f"parent:{explorer}", "powershell.exe", min_baseline=3) is False


def test_real_encoded_payload_has_higher_entropy_than_typical_admin_scripts() -> None:
    encoded = (
        "powershell.exe -NoP -W Hidden -EncodedCommand "
        "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
    )
    admin = "powershell.exe Get-Service | Where-Object Status -eq Running"
    e_enc, e_admin = command_line_entropy(encoded), command_line_entropy(admin)
    assert e_enc is not None and e_admin is not None and e_enc > e_admin


# ------------------------------------------------------------------ normalizer


def test_process_create_maps_all_fields() -> None:
    raw = winpulse(
        4688,
        "process_create",
        {
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ParentProcessName": "C:\\Windows\\explorer.exe",
            "SubjectUserName": "alice",
            "SubjectDomainName": "CORP",
        },
    )
    ev = normalize_winpulse(raw)
    assert ev is not None
    assert ev.source == "endpoint" and ev.event_type == "process_create"
    assert ev.process_name == "C:\\Windows\\System32\\cmd.exe"
    assert ev.parent_process == "C:\\Windows\\explorer.exe"
    assert ev.command_line == "cmd.exe /c whoami"
    assert ev.user == "CORP\\alice"
    assert ev.src_ip == "WORKSTATION-07"
    assert ev.label is None  # raw WinPulse carries no ground truth


def test_process_create_without_domain_uses_bare_username() -> None:
    raw = winpulse(4688, "process_create", {"NewProcessName": "x", "SubjectUserName": "bob"})
    ev = normalize_winpulse(raw)
    assert ev is not None and ev.user == "bob"


def test_service_install_maps_image_path_to_command_line() -> None:
    raw = winpulse(
        7045,
        "service_install",
        {
            "ServiceName": "UpdSvc",
            "ImagePath": "C:\\Users\\Public\\upd.exe",
            "AccountName": "LocalSystem",
        },
    )
    ev = normalize_winpulse(raw)
    assert ev is not None
    assert ev.event_type == "service_install"
    assert ev.process_name == "UpdSvc"
    assert ev.command_line == "C:\\Users\\Public\\upd.exe"
    assert ev.user == "LocalSystem"


def test_powershell_script_block_maps_script_text_to_command_line() -> None:
    raw = winpulse(
        4104,
        "powershell_script_block",
        {"ScriptBlockText": "Get-Process", "UserId": "CORP\\carol"},
    )
    ev = normalize_winpulse(raw)
    assert ev is not None
    assert ev.event_type == "powershell_script_block"
    assert (
        ev.process_name == "powershell.exe"
    )  # 4104 implies PowerShell; not literally in the event
    assert ev.command_line == "Get-Process"
    assert ev.user == "CORP\\carol"


@pytest.mark.parametrize(
    "raw",
    [
        {"event_id": 9999, "data": {}},  # unknown event id
        {"event_id": 4688},  # missing data
        {"event_id": 4688, "data": "not-a-dict"},
        {},
    ],
)
def test_unmappable_records_are_dropped(raw: dict[str, object]) -> None:
    assert normalize_winpulse(raw) is None


@pytest.mark.parametrize("payload", [b"not json", b"[]", b"123", b"null", b"\xff\xfe", b""])
def test_normalize_message_never_raises(payload: bytes) -> None:
    assert normalize_message(payload) is None


def test_hostile_values_are_bounded_not_rejected() -> None:
    raw = winpulse(
        4688,
        "process_create",
        {
            "NewProcessName": "A" * 100_000,
            "CommandLine": "B" * 100_000,
            "ParentProcessName": "C" * 100_000,
            "SubjectUserName": "d" * 100_000,
        },
    )
    ev = normalize_winpulse(raw)
    assert ev is not None
    assert len(ev.process_name or "") == MAX_LEN["process_name"]
    assert len(ev.command_line or "") == MAX_LEN["command_line"]
    assert len(ev.parent_process or "") == MAX_LEN["parent_process"]


def test_bad_timestamp_falls_back_to_now() -> None:
    raw = winpulse(4688, "process_create", {"NewProcessName": "x"}, ts="not-a-number")
    ev = normalize_winpulse(raw)
    assert ev is not None and ev.timestamp_generated > 1_000_000_000


def test_label_cannot_be_smuggled_in_from_a_raw_log() -> None:
    raw = winpulse(4688, "process_create", {"NewProcessName": "x", "label": "malicious"})
    ev = normalize_winpulse(raw)
    assert ev is not None and ev.label is None


# ------------------------------------------------------------------ sample logs -> rules


def _load_sample(name: str) -> list[dict[str, object]]:
    path = SAMPLES / f"{name}.jsonl"
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_sample_logs_exist_and_parse() -> None:
    for name in ("process_create", "service_install", "powershell_script_block"):
        rows = _load_sample(name)
        assert len(rows) >= 3
        for row in rows:
            assert normalize_winpulse(row) is not None


def test_sen010_fires_on_office_app_spawning_shell_not_on_normal_use() -> None:
    engine = RuleEngine(MemoryStore())
    rows = _load_sample("process_create")
    fired = []
    for row in rows:
        ev = normalize_winpulse(row)
        assert ev is not None
        fired.append({d.rule_id for d in engine.evaluate(ev)})
    # rows 0-2 are benign browsing/editing/mail; rows 3-5 are office apps spawning a shell
    assert all("SEN-010" not in f for f in fired[:3])
    assert all("SEN-010" in f for f in fired[3:6])


def test_sen011_fires_only_on_the_encoded_powershell_sample() -> None:
    engine = RuleEngine(MemoryStore())
    rows = _load_sample("process_create")
    fired = [{d.rule_id for d in engine.evaluate(normalize_winpulse(row))} for row in rows]  # type: ignore[arg-type]
    assert "SEN-011" in fired[5]  # the -EncodedCommand row
    assert all("SEN-011" not in f for f in fired[:5])


def test_sen012_fires_only_on_the_user_writable_service_path() -> None:
    engine = RuleEngine(MemoryStore())
    rows = _load_sample("service_install")
    fired = [{d.rule_id for d in engine.evaluate(normalize_winpulse(row))} for row in rows]  # type: ignore[arg-type]
    assert fired[:2] == [set(), set()]  # HP and WaaS: real, legitimate services on this machine
    assert "SEN-012" in fired[2]  # UpdSvc in C:\Users\Public


def test_sen011_fires_on_encoded_powershell_script_block() -> None:
    engine = RuleEngine(MemoryStore())
    rows = _load_sample("powershell_script_block")
    fired = [{d.rule_id for d in engine.evaluate(normalize_winpulse(row))} for row in rows]  # type: ignore[arg-type]
    assert fired[0] == set() and fired[1] == set()  # ordinary admin script blocks
    assert fired[2] == set()  # plain-text download cradle: not encoded, out of scope for SEN-011
    assert "SEN-011" in fired[3]  # the literal -EncodedCommand block
