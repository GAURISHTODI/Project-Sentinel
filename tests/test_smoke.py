import json
import logging

import sentinel
from sentinel.common.config import get_settings
from sentinel.common.logging import JsonFormatter


def test_package_importable() -> None:
    assert sentinel.__doc__ is not None or sentinel.__name__ == "sentinel"


def test_settings_defaults() -> None:
    s = get_settings()
    assert s.events_topic == "events.normalized"


def test_secrets_not_leaked_in_repr() -> None:
    s = get_settings()
    assert "password" not in repr(s).lower() or "**********" in repr(s)


def test_json_log_format() -> None:
    rec = logging.LogRecord("t", logging.INFO, __file__, 1, "hello %s", ("x",), None)
    out = json.loads(JsonFormatter().format(rec))
    assert out["msg"] == "hello x" and out["level"] == "INFO"
