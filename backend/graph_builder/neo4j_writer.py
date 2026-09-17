"""Thin Neo4j loading layer.

Deliberately dumb: it takes an already-built Graph and a driver (constructed
by the caller, so it's trivial to substitute a mock in tests) and emits
batched, idempotent UNWIND + MERGE Cypher. No parsing or merge logic lives
here — that's graph_builder.cyclonedx_parser / graph_builder.graph_merge,
which are tested without any database in scope.
"""

from __future__ import annotations

from typing import Any, Iterable

from .models import Graph
from .neo4j_batch import run_batched

DEFAULT_BATCH_SIZE = 500

_CONSTRAINT_QUERIES = [
    "CREATE CONSTRAINT app_id_unique IF NOT EXISTS "
    "FOR (a:Application) REQUIRE a.app_id IS UNIQUE",
    "CREATE CONSTRAINT package_key_unique IF NOT EXISTS "
    "FOR (p:Package) REQUIRE (p.name, p.version, p.ecosystem) IS UNIQUE",
]

_APPLICATION_QUERY = "UNWIND $rows AS row MERGE (a:Application {app_id: row.app_id})"

_PACKAGE_QUERY = (
    "UNWIND $rows AS row "
    "MERGE (p:Package {name: row.name, version: row.version, ecosystem: row.ecosystem})"
)

_DEPENDS_ON_QUERY = (
    "UNWIND $rows AS row "
    "MATCH (a:Application {app_id: row.app_id}) "
    "MATCH (p:Package {name: row.name, version: row.version, ecosystem: row.ecosystem}) "
    "MERGE (a)-[r:DEPENDS_ON]->(p) "
    "SET r.direct = row.direct, r.depth = row.depth"
)

_REQUIRES_QUERY = (
    "UNWIND $rows AS row "
    "MATCH (p1:Package {name: row.sn, version: row.sv, ecosystem: row.se}) "
    "MATCH (p2:Package {name: row.tn, version: row.tv, ecosystem: row.te}) "
    "MERGE (p1)-[:REQUIRES]->(p2)"
)


class Neo4jWriter:
    def __init__(self, driver: Any, batch_size: int = DEFAULT_BATCH_SIZE):
        self.driver = driver
        self.batch_size = batch_size

    def ensure_constraints(self) -> None:
        with self.driver.session() as session:
            for query in _CONSTRAINT_QUERIES:
                session.run(query)

    def write_graph(self, graph: Graph) -> None:
        self.ensure_constraints()
        self._write_applications(graph.applications)
        self._write_packages(graph.packages)
        self._write_depends_on(graph.depends_on.values())
        self._write_requires(graph.requires)

    def _run_batched(self, query: str, rows: list[dict]) -> None:
        run_batched(self.driver, query, rows, self.batch_size)

    def _write_applications(self, applications: Iterable[str]) -> None:
        rows = [{"app_id": app_id} for app_id in sorted(applications)]
        self._run_batched(_APPLICATION_QUERY, rows)

    def _write_packages(self, packages: Iterable) -> None:
        rows = [
            {"name": p.name, "version": p.version, "ecosystem": p.ecosystem}
            for p in packages
        ]
        self._run_batched(_PACKAGE_QUERY, rows)

    def _write_depends_on(self, edges: Iterable) -> None:
        rows = [
            {
                "app_id": e.app_id,
                "name": e.package.name,
                "version": e.package.version,
                "ecosystem": e.package.ecosystem,
                "direct": e.direct,
                "depth": e.depth,
            }
            for e in edges
        ]
        self._run_batched(_DEPENDS_ON_QUERY, rows)

    def _write_requires(self, edges: Iterable) -> None:
        rows = [
            {
                "sn": src.name, "sv": src.version, "se": src.ecosystem,
                "tn": tgt.name, "tv": tgt.version, "te": tgt.ecosystem,
            }
            for (src, tgt) in edges
        ]
        self._run_batched(_REQUIRES_QUERY, rows)
