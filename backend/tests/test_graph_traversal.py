"""Tests for the shared BFS primitive itself, independent of either
caller's wrapper (structural_metrics.blast_radius / compromise_simulation.
simulate_compromise), which have their own tests covering their specific
defaults."""

from __future__ import annotations

import networkx as nx

from graph_builder.graph_traversal import package_requires_subgraph, reverse_requires_walk
from graph_builder.models import PackageKey

A = PackageKey("a", "1.0.0", "npm")
B = PackageKey("b", "1.0.0", "npm")


def _graph():
    graph = nx.DiGraph()
    graph.add_node("app1", node_type="application")
    graph.add_node(A, node_type="package", name="a", version="1.0.0", ecosystem="npm")
    graph.add_node(B, node_type="package", name="b", version="1.0.0", ecosystem="npm")
    graph.add_edge("app1", A, edge_type="DEPENDS_ON", direct=True, depth=1)
    graph.add_edge(A, B, edge_type="REQUIRES")
    return graph


def test_package_requires_subgraph_drops_application_nodes():
    subgraph = package_requires_subgraph(_graph())
    assert set(subgraph.nodes()) == {A, B}


def test_respect_blocks_propagation_true_is_the_default():
    graph = _graph()
    graph.edges[A, B]["blocks_propagation"] = True
    result = reverse_requires_walk(graph, B)
    assert result.compromised_packages == {B}  # A not reached, default respects the block


def test_respect_blocks_propagation_false_ignores_the_attribute():
    graph = _graph()
    graph.edges[A, B]["blocks_propagation"] = True
    result = reverse_requires_walk(graph, B, respect_blocks_propagation=False)
    assert result.compromised_packages == {A, B}  # block ignored


def test_blocked_edges_param_works_even_when_not_respecting_graph_attribute():
    graph = _graph()
    result = reverse_requires_walk(graph, B, respect_blocks_propagation=False, blocked_edges={(A, B)})
    assert result.compromised_packages == {B}  # explicit override still applies
