"""Slack / Microsoft Teams webhook notifier. Mockable: pass an httpx transport in tests.

Detection fields come from logs and are attacker-controlled, so they are cleaned and length-bounded
before they reach a chat channel, and the webhook client never follows redirects.
"""

from __future__ import annotations

import httpx

from sentinel.common.logging import get_logger
from sentinel.common.schema import Detection
from sentinel.common.security import clean_text

log = get_logger(__name__)


class Notifier:
    def __init__(
        self,
        webhook_url: str | None,
        flavor: str = "slack",
        transport: httpx.BaseTransport | None = None,
        timeout: float = 3.0,
    ) -> None:
        if flavor not in {"slack", "teams"}:
            raise ValueError("flavor must be 'slack' or 'teams'")
        if (
            webhook_url
            and not webhook_url.startswith("https://")
            and "127.0.0.1" not in webhook_url
        ):
            raise ValueError("webhook must be https (plain http only for local testing)")
        self.url, self.flavor = webhook_url, flavor
        self._client = httpx.Client(transport=transport, timeout=timeout, follow_redirects=False)

    def message(self, det: Detection) -> str:
        who = clean_text(det.src_ip or det.user or "unknown", 60)
        detector = clean_text(det.rule_id or det.model_name, 40)
        return (
            f"[{det.severity.upper()}] {detector} ({det.attack_id or 'n/a'}) from {who}: "
            f"{clean_text(det.explanation, 300)}"
        )

    def send(self, det: Detection) -> bool:
        """True if delivered. With no webhook configured it only logs (still returns False)."""
        text = self.message(det)
        if not self.url:
            log.info("notify (no webhook configured)", extra={"fields": {"text": text}})
            return False
        payload = {"text": text}  # Slack and Teams incoming webhooks both accept {"text": ...}
        try:
            resp = self._client.post(self.url, json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            log.error("notify failed", extra={"fields": {"error": clean_text(exc, 200)}})
            return False
        return True
