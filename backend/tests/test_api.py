"""HTTP-layer tests for Phase 8's API.

The underlying logic (simulate_compromise, rank_mitigations, scoring) is
already unit-tested elsewhere -- these tests focus on status codes, JSON
shape, and routing/encoding edge cases (package ids with "/" and "@").

Deliberately does NOT need a live Neo4j for any of this: `state` (the
module-level singleton graph_builder.api.state) is populated directly with
hand-built fixture data before each test, and TestClient is used WITHOUT
the `with` context manager -- Starlette only runs lifespan (which is what
would try to reach Neo4j) inside a `with TestClient(app) as client:` block,
so omitting it means these requests never touch Neo4j at all. The one
test that actually exercises the real startup path against a live Neo4j is
separate (test_api_live.py) and skips cleanly if Neo4j isn't reachable,
mirroring this project's existing live-test pattern.
"""

from __future__ import annotations

import networkx as nx
import pytest
from fastapi.testclient import TestClient

from graph_builder.api import app, state
from graph_builder.api_data import PackageApiData
from graph_builder.models import PackageKey

LODASH = PackageKey("lodash", "4.17.21", "npm")
SCOPED = PackageKey("@babel/helper-string-parser", "7.29.7", "npm")
X = PackageKey("x", "1.0.0", "npm")


def _fixture_graph() -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node("app1", node_type="application")
    g.add_node("app2", node_type="application")
    g.add_node(X, node_type="package", name="x", version="1.0.0", ecosystem="npm")
    g.add_node(LODASH, node_type="package", name="lodash", version="4.17.21", ecosystem="npm")
    g.add_node(SCOPED, node_type="package", name="@babel/helper-string-parser", version="7.29.7", ecosystem="npm")

    g.add_edge("app1", X, edge_type="DEPENDS_ON", direct=True, depth=1)
    g.add_edge("app2", LODASH, edge_type="DEPENDS_ON", direct=True, depth=1)
    g.add_edge("app1", SCOPED, edge_type="DEPENDS_ON", direct=True, depth=1)
    g.add_edge(X, LODASH, edge_type="REQUIRES")

    # give the package nodes the score attributes /graph is supposed to bake in
    g.nodes[X].update({"risk_score": 0.3, "fan_in": 1, "betweenness_centrality": 0.0})
    g.nodes[LODASH].update({"risk_score": 0.7, "fan_in": 2, "betweenness_centrality": 0.1})
    g.nodes[SCOPED].update({"risk_score": 0.1, "fan_in": 1, "betweenness_centrality": 0.0})
    return g


def _fixture_package_data() -> dict[PackageKey, PackageApiData]:
    return {
        LODASH: PackageApiData(
            package=LODASH, fan_in=2, depth=1, betweenness_centrality=0.1,
            blast_radius_apps=["app1", "app2"],
            raw_factors={"cvss_normalized": 0.5, "exploitability": 0.3, "centrality_normalized": 0.1, "blast_radius_ratio": 0.5, "runtime_exposure": 0.6},
            weighted_terms={"cvss_normalized": 0.1, "exploitability": 0.06, "centrality_normalized": 0.02, "blast_radius_ratio": 0.1, "runtime_exposure": 0.12},
            risk_score=0.7,
            vulnerabilities=[{"id": "CVE-2021-23337", "id_type": "cve", "cvss_score": 7.2, "cvss_severity": "HIGH", "cvss_source": "osv", "epss_score": 0.02, "epss_percentile": 0.8}],
        ),
        X: PackageApiData(package=X, fan_in=1, blast_radius_apps=["app1"], risk_score=0.3),
        SCOPED: PackageApiData(package=SCOPED, fan_in=1, blast_radius_apps=["app1"], risk_score=0.1),
    }


def _fixture_mitigations() -> list[dict]:
    return [
        {
            "package": {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
            "risk_score_before": 0.7, "risk_score_after": 0.4, "risk_reduction": 0.3,
            "fixed_version": "4.17.22", "effort": 1, "priority": 0.3,
            "explanation": "high CVE (CVSS 7.2), affects 2 of 2 apps",
        },
    ]


@pytest.fixture(autouse=True)
def _populate_state():
    state.graph = _fixture_graph()
    state.package_data = _fixture_package_data()
    state.mitigations = _fixture_mitigations()
    yield
    state.graph = None
    state.package_data = {}
    state.mitigations = []


@pytest.fixture
def client():
    return TestClient(app)  # no `with` -- lifespan (and its Neo4j call) never runs


# --- GET /graph ---

def test_get_graph_status_and_shape(client):
    resp = client.get("/graph")
    assert resp.status_code == 200
    body = resp.json()
    assert "nodes" in body and "edges" in body
    assert len(body["nodes"]) == 5  # 2 apps + 3 packages
    assert len(body["edges"]) == 4


def test_get_graph_package_nodes_carry_computed_attributes(client):
    body = client.get("/graph").json()
    lodash_node = next(n for n in body["nodes"] if n["type"] == "package" and n["name"] == "lodash")
    assert lodash_node["risk_score"] == 0.7
    assert lodash_node["fan_in"] == 2
    assert lodash_node["betweenness_centrality"] == 0.1
    assert lodash_node["ecosystem"] == "npm"


def test_get_graph_application_nodes_shaped_correctly(client):
    body = client.get("/graph").json()
    app_node = next(n for n in body["nodes"] if n["type"] == "application")
    assert app_node["id"] in ("app1", "app2")
    assert app_node["name"] == app_node["id"]


def test_get_graph_edges_carry_type_specific_fields(client):
    body = client.get("/graph").json()
    depends_on = next(e for e in body["edges"] if e["type"] == "DEPENDS_ON")
    assert "direct" in depends_on and "depth" in depends_on
    requires = next(e for e in body["edges"] if e["type"] == "REQUIRES")
    assert "blocks_propagation" in requires


def test_get_graph_scoped_package_id_round_trips(client):
    body = client.get("/graph").json()
    scoped_node = next(n for n in body["nodes"] if n["name"] == "@babel/helper-string-parser")
    assert scoped_node["id"] == "npm:@babel/helper-string-parser@7.29.7"


# --- GET /package/{id} ---

def test_get_package_found(client):
    resp = client.get("/package/npm:lodash@4.17.21")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "lodash"
    assert body["risk_score"] == 0.7
    assert body["raw_factors"]["cvss_normalized"] == 0.5
    assert body["weighted_terms"]["cvss_normalized"] == 0.1
    assert len(body["vulnerabilities"]) == 1
    assert body["vulnerabilities"][0]["id"] == "CVE-2021-23337"
    assert body["vulnerabilities"][0]["cvss_score"] == 7.2


def test_get_package_not_found_returns_404_with_plain_error_body(client):
    resp = client.get("/package/npm:does-not-exist@1.0.0")
    assert resp.status_code == 404
    assert resp.json() == {"error": "package not found"}


def test_get_package_malformed_id_returns_400(client):
    resp = client.get("/package/not-a-valid-id")
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_get_package_scoped_npm_name_with_slash(client):
    # The whole point of the :path converter -- a package id containing "/"
    # must route correctly, not 404 as "not found" or 405 as bad routing.
    resp = client.get("/package/npm:@babel/helper-string-parser@7.29.7")
    assert resp.status_code == 200
    assert resp.json()["name"] == "@babel/helper-string-parser"


# --- POST /simulate/{id} ---

def test_post_simulate_without_body(client):
    resp = client.post("/simulate/npm:lodash@4.17.21")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"compromised_packages", "compromised_apps", "trace"}
    names = {p["name"] for p in body["compromised_packages"]}
    assert names == {"lodash", "x"}  # x requires lodash, so x is compromised too
    assert set(body["compromised_apps"]) == {"app1", "app2"}
    assert body["trace"] == [{"from": "npm:x@1.0.0", "to": "npm:lodash@4.17.21"}]


def test_post_simulate_with_empty_body(client):
    resp = client.post("/simulate/npm:lodash@4.17.21", json={})
    assert resp.status_code == 200
    assert "x" in {p["name"] for p in resp.json()["compromised_packages"]}


def test_post_simulate_with_blocked_edges_body(client):
    resp = client.post(
        "/simulate/npm:lodash@4.17.21",
        json={"blocked_edges": [["npm:x@1.0.0", "npm:lodash@4.17.21"]]},
    )
    assert resp.status_code == 200
    body = resp.json()
    names = {p["name"] for p in body["compromised_packages"]}
    assert names == {"lodash"}  # x is protected now
    assert "app1" not in body["compromised_apps"]
    assert body["trace"] == []


def test_post_simulate_unknown_package_returns_404(client):
    resp = client.post("/simulate/npm:does-not-exist@1.0.0")
    assert resp.status_code == 404
    assert resp.json() == {"error": "package not found"}


def test_post_simulate_malformed_blocked_edge_returns_400(client):
    resp = client.post(
        "/simulate/npm:lodash@4.17.21",
        json={"blocked_edges": [["not-a-valid-id", "npm:lodash@4.17.21"]]},
    )
    assert resp.status_code == 400


def test_post_simulate_malformed_package_id_returns_400(client):
    resp = client.post("/simulate/not-a-valid-id")
    assert resp.status_code == 400


# --- GET /mitigations ---

def test_get_mitigations_status_and_shape(client):
    resp = client.get("/mitigations")
    assert resp.status_code == 200
    body = resp.json()
    assert "mitigations" in body
    assert len(body["mitigations"]) == 1
    entry = body["mitigations"][0]
    assert entry["package"]["name"] == "lodash"
    assert entry["risk_reduction"] == 0.3
    assert entry["explanation"]


# --- cross-cutting: consistent error shape ---

@pytest.mark.parametrize("method,path", [
    ("get", "/package/not-a-valid-id"),
    ("post", "/simulate/not-a-valid-id"),
    ("get", "/package/npm:nope@1.0.0"),
])
def test_error_responses_always_have_error_key_only(client, method, path):
    resp = getattr(client, method)(path)
    assert resp.status_code >= 400
    body = resp.json()
    assert "error" in body
    assert "detail" not in body  # not FastAPI's default shape


def test_cors_header_present(client):
    resp = client.get("/graph", headers={"Origin": "http://localhost:5173"})
    assert resp.headers.get("access-control-allow-origin") == "*"
