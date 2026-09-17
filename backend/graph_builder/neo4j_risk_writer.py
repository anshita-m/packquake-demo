"""Thin Neo4j write-back layer for Phase 6: writes the 5 raw factors, the 5
weighted terms, and risk_score onto each Package node.

Same pattern as neo4j_metrics_writer.py: batched UNWIND, MATCH + SET (the
Package nodes already exist), idempotent -- re-running always sets the same
computed values for the same inputs.
"""

from __future__ import annotations

from typing import Any

from .models import PackageKey
from .neo4j_batch import run_batched
from .risk_score import RAW_FACTOR_NAMES

DEFAULT_BATCH_SIZE = 500

_SET_CLAUSES = ", ".join(f"p.{name} = row.{name}" for name in RAW_FACTOR_NAMES)
_WEIGHTED_SET_CLAUSES = ", ".join(f"p.weighted_{name} = row.weighted_{name}" for name in RAW_FACTOR_NAMES)

_RISK_QUERY = (
    "UNWIND $rows AS row "
    "MATCH (p:Package {name: row.name, version: row.version, ecosystem: row.ecosystem}) "
    f"SET {_SET_CLAUSES}, {_WEIGHTED_SET_CLAUSES}, p.risk_score = row.risk_score"
)


class Neo4jRiskWriter:
    def __init__(self, driver: Any, batch_size: int = DEFAULT_BATCH_SIZE):
        self.driver = driver
        self.batch_size = batch_size

    def write_risk_scores(self, scored: dict[PackageKey, dict]) -> None:
        """`scored` is {PackageKey: {"raw_factors": {...}, "weighted_terms": {...}, "risk_score": float}}."""
        rows = []
        for pkg, entry in scored.items():
            row = {"name": pkg.name, "version": pkg.version, "ecosystem": pkg.ecosystem, "risk_score": entry["risk_score"]}
            for name in RAW_FACTOR_NAMES:
                row[name] = entry["raw_factors"][name]
                row[f"weighted_{name}"] = entry["weighted_terms"][name]
            rows.append(row)
        run_batched(self.driver, _RISK_QUERY, rows, self.batch_size)
