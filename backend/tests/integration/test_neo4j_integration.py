"""Live Neo4j integration test.

Skips cleanly if Neo4j isn't reachable. To run it for real:

    docker-compose up -d
    pytest backend/tests/integration -v
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

neo4j = pytest.importorskip("neo4j")

from graph_builder.cyclonedx_parser import parse_sbom_file  # noqa: E402
from graph_builder.graph_merge import merge_apps  # noqa: E402
from graph_builder.neo4j_writer import Neo4jWriter  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "password")


def _neo4j_available() -> bool:
    try:
        driver = neo4j.GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        try:
            driver.verify_connectivity()
            return True
        finally:
            driver.close()
    except Exception:
        return False


requires_live_neo4j = pytest.mark.skipif(
    not _neo4j_available(),
    reason=f"Neo4j not reachable at {NEO4J_URI}; run `docker-compose up -d` to test live.",
)


@pytest.mark.live
@requires_live_neo4j
def test_load_graph_and_verify_accepts_fan_in():
    """accepts@1.3.8 is a real package naturally shared by hackathon-starter
    and node-realworld's actual Syft scans -- see cli.py's SANITY_CHECKS
    comment for why this replaced the old lodash/requests planted-pin check."""
    sbom_dir = REPO_ROOT / "data" / "sbom"
    parsed_apps = [parse_sbom_file(p) for p in sorted(sbom_dir.glob("*.json"))]
    graph = merge_apps(parsed_apps)

    driver = neo4j.GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")  # clean slate for a deterministic assertion

        Neo4jWriter(driver).write_graph(graph)

        with driver.session() as session:
            result = session.run(
                "MATCH (a:Application)-[:DEPENDS_ON]->"
                "(p:Package {name: 'accepts', version: '1.3.8', ecosystem: 'npm'}) "
                "RETURN count(DISTINCT a) AS n"
            )
            assert result.single()["n"] == 2

        # Re-running the load must not create duplicates (idempotent MERGE).
        Neo4jWriter(driver).write_graph(graph)
        with driver.session() as session:
            result = session.run("MATCH (p:Package) RETURN count(p) AS n")
            assert result.single()["n"] == len(graph.packages)
    finally:
        driver.close()
