"""Phase 5 tests.

Fixture is built EXACTLY as specified in the brief: "A depends on X, X
requires lodash, B depends on lodash directly" -- i.e. only two DEPENDS_ON
facts (A->X, B->lodash), not the fuller transitive closure a real Phase 2
BFS would also record (A->lodash, depth 2). That's deliberate: it's what
makes the blocking test (test 2) meaningful. If A also carried its own
direct-or-transitive DEPENDS_ON->lodash edge (as Phase 2 would give it in
the live system), compromised_apps would trivially include A regardless of
blocking, since rule #3 is a flat lookup over DEPENDS_ON edges -- it
wouldn't prove blocking actually did anything. Keeping the fixture minimal
isolates exactly the mechanism being tested.
"""

from __future__ import annotations

from pathlib import Path

import networkx as nx
import pytest

from graph_builder.compromise_simulation import simulate_compromise
from graph_builder.cyclonedx_parser import parse_sbom_file
from graph_builder.graph_merge import merge_apps
from graph_builder.models import PackageKey

X = PackageKey("x", "1.0.0", "npm")
LODASH = PackageKey("lodash", "4.17.21", "npm")

REPO_ROOT = Path(__file__).resolve().parents[2]


def _fixture_graph() -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_node("A", node_type="application")
    graph.add_node("B", node_type="application")
    graph.add_node(X, node_type="package", name=X.name, version=X.version, ecosystem=X.ecosystem)
    graph.add_node(LODASH, node_type="package", name=LODASH.name, version=LODASH.version, ecosystem=LODASH.ecosystem)

    graph.add_edge("A", X, edge_type="DEPENDS_ON", direct=True, depth=1)
    graph.add_edge("B", LODASH, edge_type="DEPENDS_ON", direct=True, depth=1)
    graph.add_edge(X, LODASH, edge_type="REQUIRES")

    return graph


# --- Test 1: unblocked propagation ---

def test_simulate_compromise_unblocked_reaches_both_apps():
    result = simulate_compromise(_fixture_graph(), LODASH)

    assert result["compromised_packages"] == {LODASH, X}
    assert result["compromised_apps"] == {"A", "B"}
    assert (X, LODASH) in result["trace"]
    assert len(result["trace"]) == 1


# --- Test 2: blocks_propagation actually stops propagation ---

def test_simulate_compromise_respects_blocks_propagation_edge_attribute():
    graph = _fixture_graph()
    graph.edges[X, LODASH]["blocks_propagation"] = True

    result = simulate_compromise(graph, LODASH)

    assert result["compromised_packages"] == {LODASH}  # X never reached
    assert result["compromised_apps"] == {"B"}  # A is protected
    assert result["trace"] == []  # the blocked edge was never crossed


def test_simulate_compromise_blocked_edges_param_has_same_effect():
    # Same outcome via the ad-hoc override instead of a graph attribute --
    # useful for "what if we blocked this" without writing to Neo4j first.
    graph = _fixture_graph()

    result = simulate_compromise(graph, LODASH, blocked_edges={(X, LODASH)})

    assert result["compromised_packages"] == {LODASH}
    assert result["compromised_apps"] == {"B"}
    assert result["trace"] == []


def test_unblocked_and_blocked_results_actually_differ():
    unblocked = simulate_compromise(_fixture_graph(), LODASH)

    blocked_graph = _fixture_graph()
    blocked_graph.edges[X, LODASH]["blocks_propagation"] = True
    blocked = simulate_compromise(blocked_graph, LODASH)

    assert unblocked["compromised_apps"] != blocked["compromised_apps"]
    assert "A" in unblocked["compromised_apps"]
    assert "A" not in blocked["compromised_apps"]


# --- trace direction ---

def test_trace_direction_matches_storage_not_walk_order():
    # We walk FROM lodash outward (reverse), but the trace tuple must read
    # (dependent, dependency) -- the same direction REQUIRES is stored --
    # not (lodash, X), which would be the walk direction.
    result = simulate_compromise(_fixture_graph(), LODASH)
    assert result["trace"] == [(X, LODASH)]


# --- absent blocks_propagation defaults to unblocked ---

def test_missing_blocks_propagation_attribute_means_unblocked():
    graph = _fixture_graph()
    assert "blocks_propagation" not in graph.edges[X, LODASH]
    result = simulate_compromise(graph, LODASH)
    assert X in result["compromised_packages"]


def test_blocks_propagation_false_means_unblocked():
    graph = _fixture_graph()
    graph.edges[X, LODASH]["blocks_propagation"] = False
    result = simulate_compromise(graph, LODASH)
    assert X in result["compromised_packages"]


# --- Test 3: the real Phase 2/4 graph ---

def _real_graph() -> nx.DiGraph:
    sbom_dir = REPO_ROOT / "data" / "sbom"
    parsed_apps = [parse_sbom_file(p) for p in sorted(sbom_dir.glob("*.json"))]
    merged = merge_apps(parsed_apps)

    graph = nx.DiGraph()
    for app_id in merged.applications:
        graph.add_node(app_id, node_type="application")
    for pkg in merged.packages:
        graph.add_node(pkg, node_type="package", name=pkg.name, version=pkg.version, ecosystem=pkg.ecosystem)
    for (app_id, pkg), edge in merged.depends_on.items():
        graph.add_edge(app_id, pkg, edge_type="DEPENDS_ON", direct=edge.direct, depth=edge.depth)
    for (src, tgt) in merged.requires:
        graph.add_edge(src, tgt, edge_type="REQUIRES")
    return graph


def test_simulate_compromise_against_real_graph_matches_expected_apps():
    # accepts@1.3.8 is a real package naturally shared (same name+version)
    # by hackathon-starter and node-realworld's actual Syft scans -- not a
    # planted pin (lodash isn't in either real SBOM; see cli.py's
    # SANITY_CHECKS comment for the full story).
    sbom_dir = REPO_ROOT / "data" / "sbom"
    if not sbom_dir.exists() or not any(sbom_dir.glob("*.json")):
        pytest.skip("data/sbom fixtures not present")

    graph = _real_graph()
    accepts = PackageKey("accepts", "1.3.8", "npm")

    result = simulate_compromise(graph, accepts)

    assert result["compromised_apps"] == {"hackathon-starter", "node-realworld"}
    assert accepts in result["compromised_packages"]
