"""Triage one stored incident: python -m sentinel.triage.run --incident-id 12

Reads the incident from PostgreSQL and prints a schema-validated report. Nothing is executed or
changed: the report is a suggestion for an analyst. Stored incidents keep no raw event fields
(user agent, path, command line), so only the explanation, username and source IP reach the model.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import psycopg

from sentinel.common.config import dsn_for, get_settings
from sentinel.triage.agent import IncidentInput, TriageAgent
from sentinel.triage.llm import GeminiClient, LLMClient, MockLLM

AUDIT = Path("data/triage_audit.jsonl")


def make_client() -> LLMClient:
    cfg = get_settings()
    if cfg.llm_provider == "mock":
        return MockLLM()
    if cfg.llm_provider == "gemini":
        return GeminiClient(cfg.llm_api_key.get_secret_value())
    raise SystemExit(f"unsupported LLM_PROVIDER {cfg.llm_provider!r}; use mock or gemini")


def load_incident(incident_id: int) -> IncidentInput:
    dsn = dsn_for(get_settings(), "reader")
    with psycopg.connect(dsn) as conn:
        row = conn.execute(
            "SELECT id, rule_id, model_name, attack_id, severity, host(src_ip), username, "
            "explanation FROM incidents WHERE id = %s",
            (incident_id,),
        ).fetchone()
    if row is None:
        raise SystemExit(f"no incident {incident_id}")
    return IncidentInput(
        incident_id=int(row[0]),
        detector=str(row[1] or row[2]),
        attack_id=row[3],
        severity=str(row[4]),
        src_ip=row[5],
        explanation=str(row[7]),
        username=row[6],
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Triage a stored incident with the LLM agent")
    ap.add_argument("--incident-id", type=int, required=True)
    a = ap.parse_args(argv)
    client = make_client()
    try:
        outcome = TriageAgent(client, audit_path=AUDIT).triage(load_incident(a.incident_id))
    finally:
        if isinstance(client, GeminiClient):
            client.close()
    print(json.dumps({"source": outcome.source, "reason": outcome.reason,
                      "report": outcome.report.model_dump()}, indent=2))  # fmt: skip
    return 0


if __name__ == "__main__":
    sys.exit(main())
