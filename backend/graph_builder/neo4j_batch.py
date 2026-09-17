"""Shared batching helper for Neo4jWriter and Neo4jVulnWriter."""

from __future__ import annotations

from typing import Any, Iterator


def batched(rows: list[dict], batch_size: int) -> Iterator[list[dict]]:
    for i in range(0, len(rows), batch_size):
        yield rows[i : i + batch_size]


def run_batched(driver: Any, query: str, rows: list[dict], batch_size: int) -> None:
    if not rows:
        return
    with driver.session() as session:
        for batch in batched(rows, batch_size):
            session.run(query, rows=batch)
