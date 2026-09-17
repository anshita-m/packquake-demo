"""Fake requests.Session for testing the HTTP+cache client layer without
real network calls."""

from __future__ import annotations

import requests


class FakeResponse:
    def __init__(self, status_code: int = 200, json_data=None):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")


class FakeSession:
    """Pops canned responses off a queue in call order, recording every call."""

    def __init__(self, responses: list[FakeResponse]):
        self._responses = list(responses)
        self.calls: list[tuple[str, str, dict]] = []

    def post(self, url: str, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self._responses.pop(0)

    def get(self, url: str, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self._responses.pop(0)
