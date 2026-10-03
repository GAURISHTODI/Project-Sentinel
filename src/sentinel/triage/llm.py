"""LLM clients behind one interface. The agent does not depend on a specific provider.

- MockLLM: deterministic, offline. Used by the tests and by default.
- GeminiClient: Google's Gemini API (free tier via AI Studio). Reads its key from LLM_API_KEY
  and sends it in a request header only, never in a URL, log line or audit record.

The live Gemini adapter has not been run against the real endpoint: no key was available when it was
written. It is covered by a transport-mocked test of the request shape only.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Protocol

import httpx

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


class LLMClient(Protocol):
    name: str

    def complete(self, system: str, user: str, max_output_tokens: int) -> str: ...


class MockLLM:
    name = "mock"

    def __init__(self, responder: Callable[[str, str], str] | None = None) -> None:
        self._responder = responder or self._default
        self.calls = 0

    def complete(self, system: str, user: str, max_output_tokens: int) -> str:
        self.calls += 1
        return self._responder(system, user)

    @staticmethod
    def _default(system: str, user: str) -> str:
        return json.dumps(
            {
                "summary": "Deterministic mock summary; no model analysis was performed.",
                "attack_ids": ["T1190"],
                "severity": "medium",
                "recommendations": ["monitor", "escalate_to_human"],
                "confidence": 0.5,
            }
        )


class GeminiClient:
    name = "gemini"

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-2.0-flash",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("GeminiClient needs an API key")
        self._key = api_key
        self._model = model
        self._client = httpx.Client(timeout=20.0, transport=transport)

    def complete(self, system: str, user: str, max_output_tokens: int) -> str:
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {
                "maxOutputTokens": max_output_tokens,
                "temperature": 0.0,
                "responseMimeType": "application/json",
            },
        }
        resp = self._client.post(
            GEMINI_URL.format(model=self._model),
            headers={"x-goog-api-key": self._key, "content-type": "application/json"},
            json=body,
        )
        resp.raise_for_status()
        data = resp.json()
        return str(data["candidates"][0]["content"]["parts"][0]["text"])

    def close(self) -> None:
        self._client.close()
