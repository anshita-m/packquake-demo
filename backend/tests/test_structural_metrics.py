"""Hand-built graph fixture, hand-worked-out expected values.

4 apps (app1-4), 6 packages (A-F). B is shared directly by app1+app2. F
demonstrates the point of blast_radius: only app4 directly depends on F,
but F sits deep in a REQUIRES chain (D -> F) that A and B (used by app1/
app2) lead into -- so compromising F reaches app1/app2 too, even though
neither has its own DEPENDS_ON edge to F. That's a realistic outcome of
merging per-app SBOMs: one app's SBOM can record a REQUIRES edge a
different app's own scan never surfaced for the same shared package.

Structure:
  app1 -[DEPENDS_ON direct depth1]-> A, B
  app1 -[DEPENDS_ON depth2]-> C          (transitive, via A or B)
  app1 -[DEPENDS_ON depth3]-> D
  app2 -[DEPENDS_ON direct depth1]-> B
  app2 -[DEPENDS_ON depth2]-> C
  app2 -[DEPENDS_ON depth3]-> D
  app3 -[DEPENDS_ON direct depth1]-> E
  app4 -[DEPENDS_ON direct depth1]-> F

  REQUIRES: A->C, B->C, C->D, D->F
"""

from __future__ import annotations

import networkx as nx
import pytest

from graph_builder.models import PackageKey
from graph_builder.structural_metrics import (
    blast_radius,
    compute_all_metrics,
    compute_betweenness_centrality,
    depth,
    fan_in,
    package_requires_subgraph,
    reverse_requires_closure,
)

A = PackageKey("a", "1.0.0", "npm")
B = PackageKey("b", "1.0.0", "npm")
C = PackageKey("c", "1.0.0", "npm")
D = PackageKey("d", "1.0.0", "npm")
E = PackageKey("e", "1.0.0", "npm")
F = PackageKey("f", "1.0.0", "npm")


def _fixture_graph() -> nx.DiGraph:
    graph = nx.DiGraph()
    for app_id in ("app1", "app2", "app3", "app4"):
        graph.add_node(app_id, node_type="application")
    for pkg in (A, B, C, D, E, F):
        graph.add_node(pkg, node_type="package", name=pkg.name, version=pkg.version, ecosystem=pkg.ecosystem)

    graph.add_edge("app1", A, edge_type="DEPENDS_ON", direct=True, depth=1)
    graph.add_edge("app1", B, edge_type="DEPENDS_ON", direct=True, depth=1)
    graph.add_edge("app1", C, edge_type="DEPENDS_ON", direct=False, depth=2)
    graph.add_edge("app1", D, edge_type="DEPENDS_ON", direct=False, depth=3)
    graph.add_edge("app2", B, edge_type="DEPENDS_ON", direct=True, depth=1)
    graph.add_edge("app2", C, edge_type="DEPENDS_ON", direct=False, depth=2)
    graph.add_edge("app2", D, edge_type="DEPENDS_ON", direct=False, depth=3)
    graph.add_edge("app3", E, edge_type="DEPENDS_ON", direct=True, depth=1)
    graph.add_edge("app4", F, edge_type="DEPENDS_ON", direct=True, depth=1)

    graph.add_edge(A, C, edge_type="REQUIRES")
    graph.add_edge(B, C, edge_type="REQUIRES")
    graph.add_edge(C, D, edge_type="REQUIRES")
    graph.add_edge(D, F, edge_type="REQUIRES")

    return graph


# --- fan_in ---

@pytest.mark.parametrize("pkg,expected", [(A, 1), (B, 2), (C, 2), (D, 2), (E, 1), (F, 1)])
def test_fan_in(pkg, expected):
    assert fan_in(_fixture_graph(), pkg) == expected


# --- depth ---

@pytest.mark.parametrize("pkg,expected", [(A, 1), (B, 1), (C, 2), (D, 3), (E, 1), (F, 1)])
def test_depth(pkg, expected):
    assert depth(_fixture_graph(), pkg) == expected


def test_depth_of_package_with_no_depends_on_edges_is_none():
    graph = nx.DiGraph()
    orphan = PackageKey("orphan", "1.0.0", "npm")
    graph.add_node(orphan, node_type="package", name="orphan", version="1.0.0", ecosystem="npm")
    assert depth(graph, orphan) is None
    assert fan_in(graph, orphan) == 0


# --- betweenness_centrality ---

def test_package_requires_subgraph_excludes_application_nodes_and_edges():
    subgraph = package_requires_subgraph(_fixture_graph())
    assert set(subgraph.nodes()) == {A, B, C, D, E, F}
    assert all(data.get("edge_type") == "REQUIRES" for _u, _v, data in subgraph.edges(data=True))


def test_betweenness_centrality_matches_hand_computation():
    # Verified against a plain networkx.betweenness_centrality run on the
    # same 6-node/4-edge shape: C=0.2, D=0.15, everyone else 0.0.
    centrality = compute_betweenness_centrality(_fixture_graph())
    assert centrality[C] == pytest.approx(0.2)
    assert centrality[D] == pytest.approx(0.15)
    assert centrality[A] == 0.0
    assert centrality[B] == 0.0
    assert centrality[E] == 0.0
    assert centrality[F] == 0.0


def test_betweenness_centrality_excludes_application_nodes_from_result():
    centrality = compute_betweenness_centrality(_fixture_graph())
    assert "app1" not in centrality
    assert "app2" not in centrality


# --- blast_radius ---

def test_blast_radius_of_leaf_package_is_just_its_own_app():
    graph = _fixture_graph()
    assert blast_radius(graph, A) == {"app1"}
    assert blast_radius(graph, E) == {"app3"}


def test_blast_radius_of_package_shared_directly_by_two_apps():
    assert blast_radius(_fixture_graph(), B) == {"app1", "app2"}


def test_blast_radius_of_deep_transitive_package():
    graph = _fixture_graph()
    assert blast_radius(graph, C) == {"app1", "app2"}
    assert blast_radius(graph, D) == {"app1", "app2"}


def test_blast_radius_reaches_apps_with_no_direct_depends_on_edge():
    # The whole point: F's only DIRECT dependent is app4, but D->F means
    # compromising F also threatens app1/app2 (both of which use D via C).
    graph = _fixture_graph()
    assert fan_in(graph, F) == 1  # only app4 has a DEPENDS_ON edge to F
    assert blast_radius(graph, F) == {"app1", "app2", "app4"}  # but 3 apps are actually exposed


def test_blast_radius_is_not_zero_and_not_everything():
    graph = _fixture_graph()
    all_apps = {"app1", "app2", "app3", "app4"}
    for pkg in (A, B, C, D, E, F):
        result = blast_radius(graph, pkg)
        assert result, f"{pkg} should affect at least its own app"
        assert result != all_apps, f"{pkg} should not (in this fixture) reach every app"
    assert blast_radius(graph, A) != blast_radius(graph, F)


def test_reverse_requires_closure_includes_self_and_all_requirers():
    graph = _fixture_graph()
    assert reverse_requires_closure(graph, F) == {A, B, C, D, F}
    assert reverse_requires_closure(graph, A) == {A}  # nothing requires A


# --- compute_all_metrics ---

def test_compute_all_metrics_covers_every_package_with_consistent_values():
    graph = _fixture_graph()
    metrics = compute_all_metrics(graph)

    assert set(metrics.keys()) == {A, B, C, D, E, F}

    m = metrics[F]
    assert m.fan_in == 1
    assert m.depth == 1
    assert m.betweenness_centrality == 0.0
    assert m.blast_radius_apps == ["app1", "app2", "app4"]  # sorted list, not a count

    m_c = metrics[C]
    assert m_c.fan_in == 2
    assert m_c.depth == 2
    assert m_c.betweenness_centrality == pytest.approx(0.2)
    assert m_c.blast_radius_apps == ["app1", "app2"]
