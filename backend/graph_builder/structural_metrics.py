"""Pure structural-metric functions over an in-memory networkx.DiGraph
(see neo4j_reader.py for how that graph gets built). No Neo4j connection
needed here -- fully testable against a small hand-built graph fixture.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from .graph_traversal import package_requires_subgraph, reverse_requires_walk
from .models import PackageKey


def fan_in(graph: nx.DiGraph, package: PackageKey) -> int:
    """Number of distinct Applications with a DEPENDS_ON edge to `package`.

    Phase 2's DEPENDS_ON edges already represent full transitive
    reachability per app (built by a BFS over that app's whole dependency
    tree), so this is a straight count over existing edges -- no new
    traversal.
    """
    return sum(
        1 for _u, _v, data in graph.in_edges(package, data=True)
        if data.get("edge_type") == "DEPENDS_ON"
    )


def depth(graph: nx.DiGraph, package: PackageKey) -> int | None:
    """Shallowest distance from ANY app's root to `package`: the minimum
    `depth` across all its incoming DEPENDS_ON edges. None if `package` has
    no DEPENDS_ON edges at all (shouldn't happen for a package that came out
    of Phase 2, but a hand-built or partial graph could hit this)."""
    depths = [
        data["depth"] for _u, _v, data in graph.in_edges(package, data=True)
        if data.get("edge_type") == "DEPENDS_ON"
    ]
    return min(depths) if depths else None


def compute_betweenness_centrality(graph: nx.DiGraph) -> dict[PackageKey, float]:
    """Normalized betweenness centrality of every package, computed on the
    Package-only/REQUIRES-only subgraph."""
    requires_subgraph = package_requires_subgraph(graph)
    return nx.betweenness_centrality(requires_subgraph, normalized=True)


def reverse_requires_closure(graph: nx.DiGraph, package: PackageKey) -> set[PackageKey]:
    """`package` plus every package reachable by walking REQUIRES edges in
    reverse -- i.e. every package that directly or transitively requires
    `package` (REQUIRES points dependent -> dependency, so this walks
    against the edge direction). Always unconditional/worst-case: unlike
    Phase 5's simulate_compromise, this ignores blocks_propagation -- it
    answers "what COULD be reached", not "what's actually protected".

    Exposed standalone (not inlined into blast_radius) because Phase 5's
    compromise simulation needs this exact traversal with a
    propagation-blocking rule layered on top -- see graph_traversal.py,
    which both this and simulate_compromise are built on.
    """
    return reverse_requires_walk(graph, package, respect_blocks_propagation=False).compromised_packages


def blast_radius(graph: nx.DiGraph, package: PackageKey) -> set[str]:
    """Every app_id that would be affected if `package` were compromised,
    assuming nothing blocks propagation: package itself plus everything
    that (transitively) requires it, then every Application with a
    DEPENDS_ON edge to any package in that set."""
    return reverse_requires_walk(graph, package, respect_blocks_propagation=False).compromised_apps


@dataclass(frozen=True)
class PackageMetrics:
    fan_in: int
    depth: int | None
    betweenness_centrality: float
    blast_radius_apps: list[str]


def compute_all_metrics(graph: nx.DiGraph) -> dict[PackageKey, PackageMetrics]:
    """All four Phase 4 metrics for every Package node in `graph`."""
    centrality = compute_betweenness_centrality(graph)
    package_nodes = [n for n, data in graph.nodes(data=True) if data.get("node_type") == "package"]

    return {
        pkg: PackageMetrics(
            fan_in=fan_in(graph, pkg),
            depth=depth(graph, pkg),
            betweenness_centrality=centrality.get(pkg, 0.0),
            blast_radius_apps=sorted(blast_radius(graph, pkg)),
        )
        for pkg in package_nodes
    }
