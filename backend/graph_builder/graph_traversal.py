"""Shared reverse-REQUIRES BFS primitive.

Used by both Phase 4 (structural_metrics.blast_radius / reverse_requires_closure,
which always ignore blocking -- "worst case, nothing mitigated") and Phase 5
(compromise_simulation.simulate_compromise, which respects blocks_propagation
edges -- "realistic case, given current mitigations"). One traversal
implementation, not two copies of similar graph-walking code.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

import networkx as nx

from .models import PackageKey


def package_requires_subgraph(graph: nx.DiGraph) -> nx.DiGraph:
    """The Package-only subgraph: Package nodes and REQUIRES edges only.

    Excluding Application nodes/DEPENDS_ON edges is deliberate -- mixing two
    different relationship types into one traversal wouldn't mean "how does
    a compromise propagate through the shared dependency web" any more.
    """
    package_nodes = [n for n, data in graph.nodes(data=True) if data.get("node_type") == "package"]
    subgraph = graph.subgraph(package_nodes).copy()
    non_requires_edges = [
        (u, v) for u, v, data in subgraph.edges(data=True) if data.get("edge_type") != "REQUIRES"
    ]
    subgraph.remove_edges_from(non_requires_edges)
    return subgraph


@dataclass
class ReverseWalkResult:
    compromised_packages: set[PackageKey] = field(default_factory=set)
    compromised_apps: set[str] = field(default_factory=set)
    trace: list[tuple[PackageKey, PackageKey]] = field(default_factory=list)


def reverse_requires_walk(
    graph: nx.DiGraph,
    start: PackageKey,
    *,
    blocked_edges: set[tuple[PackageKey, PackageKey]] | None = None,
    respect_blocks_propagation: bool = True,
) -> ReverseWalkResult:
    """BFS from `start` over the REQUIRES graph, walking in reverse: from a
    package to everything that requires it, directly or transitively.

    A REQUIRES edge (dependent, dependency) -- e.g. ("some-package",
    "lodash") meaning some-package requires lodash -- is skipped (not
    crossed) when either:
      - `respect_blocks_propagation` is True and the edge's
        `blocks_propagation` attribute is truthy (absent/None counts as
        not blocked), or
      - the edge appears in `blocked_edges` (an ad-hoc override, for
        simulating a mitigation not yet persisted to Neo4j).

    `trace` records every edge actually crossed, in storage direction
    (dependent -> dependency) -- the same direction REQUIRES edges are
    stored in Neo4j, not the direction of the reverse walk -- covering
    every unblocked edge reachable into the compromised set, not just a
    spanning tree, so a frontend can highlight every real propagation path.
    """
    blocked = blocked_edges or set()
    requires_subgraph = package_requires_subgraph(graph)

    compromised_packages = {start}
    trace: list[tuple[PackageKey, PackageKey]] = []
    queue: deque[PackageKey] = deque([start])

    while queue:
        current = queue.popleft()
        for dependent in requires_subgraph.predecessors(current):
            edge_data = requires_subgraph.edges[dependent, current]
            edge = (dependent, current)
            if (respect_blocks_propagation and edge_data.get("blocks_propagation")) or edge in blocked:
                continue
            trace.append(edge)
            if dependent not in compromised_packages:
                compromised_packages.add(dependent)
                queue.append(dependent)

    compromised_apps = {
        app
        for pkg in compromised_packages
        for app, _v, data in graph.in_edges(pkg, data=True)
        if data.get("edge_type") == "DEPENDS_ON"
    }

    return ReverseWalkResult(compromised_packages=compromised_packages, compromised_apps=compromised_apps, trace=trace)
