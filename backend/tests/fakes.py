"""A minimal fake Neo4j driver/session for testing Neo4jWriter without a
live database. Records every (query, params) pair passed to session.run so
tests can assert on the emitted Cypher and batching behavior.
"""

from __future__ import annotations


class FakeSession:
    def __init__(self, calls: list[tuple[str, dict]]):
        self._calls = calls

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, *exc_info) -> None:
        return None

    def run(self, query: str, **kwargs):
        self._calls.append((query, kwargs))
        return None


class FakeDriver:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def session(self) -> FakeSession:
        return FakeSession(self.calls)
