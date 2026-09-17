"""Thin Neo4j write-back layer for Phase 4: sets fan_in, depth,
betweenness_centrality, and blast_radius_apps onto existing Package nodes.

Same pattern as neo4j_writer.py / neo4j_vuln_writer.py: batched UNWIND,
no logic beyond "take already-computed data, write it." Uses MATCH + SET
(not MERGE) since these Package nodes already exist -- this module only
annotates them, and re-running it always sets the same computed values, so
it's idempotent the same way the earlier MERGE-based writers are.
"""

from __future__ import annotations

from typing import Any

from .models import PackageKey
from .neo4j_batch import run_batched
from .structural_metrics import PackageMetrics

DEFAULT_BATCH_SIZE = 500

_METRICS_QUERY = (
    "UNWIND $rows AS row "
    "MATCH (p:Package {name: row.name, version: row.version, ecosystem: row.ecosystem}) "
    "SET p.fan_in = row.fan_in, "
    "    p.depth = row.depth, "
    "    p.betweenness_centrality = row.betweenness_centrality, "
    "    p.blast_radius_apps = row.blast_radius_apps"
)


class Neo4jMetricsWriter:
    def __init__(self, driver: Any, batch_size: int = DEFAULT_BATCH_SIZE):
        self.driver = driver
        self.batch_size = batch_size

    def write_metrics(self, metrics: dict[PackageKey, PackageMetrics]) -> None:
        rows = [
            {
                "name": pkg.name, "version": pkg.version, "ecosystem": pkg.ecosystem,
                "fan_in": m.fan_in,
                "depth": m.depth,
                "betweenness_centrality": m.betweenness_centrality,
                "blast_radius_apps": m.blast_radius_apps,
            }
            for pkg, m in metrics.items()
        ]
        run_batched(self.driver, _METRICS_QUERY, rows, self.batch_size)
