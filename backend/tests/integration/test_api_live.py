"""Live smoke test for Phase 8's actual startup path (the lifespan hook
that connects to Neo4j and builds state.graph/package_data/mitigations) --
everything else about the API is tested without Neo4j in tests/test_api.py.

Skips cleanly if Neo4j isn't reachable. To run it for real:

    docker-compose up -d
    python -m graph_builder.cli --sbom-dir data/sbom --load-neo4j
    python -m graph_builder.metrics_cli
    pytest backend/tests/integration -v
"""

from __future__ import annotations

import os

import pytest

neo4j = pytest.importorskip("neo4j")

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
def test_app_startup_loads_real_graph_and_responds():
    from fastapi.testclient import TestClient

    from graph_builder.api import app

    with TestClient(app) as client:  # triggers the real lifespan -> real Neo4j
        graph_resp = client.get("/graph")
        assert graph_resp.status_code == 200
        body = graph_resp.json()
        assert len(body["nodes"]) > 0
        assert len(body["edges"]) > 0

        mitigations_resp = client.get("/mitigations")
        assert mitigations_resp.status_code == 200
        assert "mitigations" in mitigations_resp.json()
