"""Thin Neo4j loading layer for Phase 3: Package -AFFECTED_BY-> Vulnerability.

Same pattern as neo4j_writer.py: takes an already-built VulnGraph and a
driver, emits batched idempotent UNWIND + MERGE Cypher, no parsing logic.
Assumes the Package nodes it MATCHes already exist (written by
Neo4jWriter.write_graph in Phase 2) -- this module only creates Vulnerability
nodes and the edges to existing Package nodes.
"""

from __future__ import annotations

from typing import Any, Iterable

from .models import VulnGraph
from .neo4j_batch import run_batched

DEFAULT_BATCH_SIZE = 500

_CONSTRAINT_QUERY = (
    "CREATE CONSTRAINT vuln_id_unique IF NOT EXISTS "
    "FOR (v:Vulnerability) REQUIRE v.vuln_id IS UNIQUE"
)

_VULNERABILITY_QUERY = (
    "UNWIND $rows AS row "
    "MERGE (v:Vulnerability {vuln_id: row.vuln_id}) "
    "SET v.id_type = row.id_type, "
    "    v.cvss_score = row.cvss_score, "
    "    v.cvss_severity = row.cvss_severity, "
    "    v.cvss_source = row.cvss_source, "
    "    v.epss_score = row.epss_score, "
    "    v.epss_percentile = row.epss_percentile"
)

_AFFECTED_BY_QUERY = (
    "UNWIND $rows AS row "
    "MATCH (p:Package {name: row.name, version: row.version, ecosystem: row.ecosystem}) "
    "MATCH (v:Vulnerability {vuln_id: row.vuln_id}) "
    "MERGE (p)-[:AFFECTED_BY]->(v)"
)


class Neo4jVulnWriter:
    def __init__(self, driver: Any, batch_size: int = DEFAULT_BATCH_SIZE):
        self.driver = driver
        self.batch_size = batch_size

    def ensure_constraints(self) -> None:
        with self.driver.session() as session:
            session.run(_CONSTRAINT_QUERY)

    def write_vuln_graph(self, vuln_graph: VulnGraph) -> None:
        self.ensure_constraints()
        self._write_vulnerabilities(vuln_graph.vulnerabilities.values())
        self._write_affected_by(vuln_graph.affected_by)

    def _write_vulnerabilities(self, vulns: Iterable) -> None:
        rows = [
            {
                "vuln_id": v.vuln_id,
                "id_type": v.id_type,
                "cvss_score": v.cvss_score,
                "cvss_severity": v.cvss_severity,
                "cvss_source": v.cvss_source,
                "epss_score": v.epss_score,
                "epss_percentile": v.epss_percentile,
            }
            for v in vulns
        ]
        run_batched(self.driver, _VULNERABILITY_QUERY, rows, self.batch_size)

    def _write_affected_by(self, edges: Iterable) -> None:
        rows = [
            {
                "name": pkg.name, "version": pkg.version, "ecosystem": pkg.ecosystem,
                "vuln_id": vuln_id,
            }
            for (pkg, vuln_id) in edges
        ]
        run_batched(self.driver, _AFFECTED_BY_QUERY, rows, self.batch_size)
