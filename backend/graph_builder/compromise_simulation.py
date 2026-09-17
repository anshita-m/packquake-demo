"""Phase 5: supply-chain compromise simulation.

A pure function over the same in-memory networkx.DiGraph shape Phase 4
reads via neo4j_reader.read_graph_from_neo4j -- load/cache that graph once,
then call simulate_compromise as many times as needed. It's meant to answer
a "click a node" interaction directly (Phase 8 will wrap it in
POST /simulate/:package_id), so it has to be fast and callable repeatedly,
not a batch job re-querying Neo4j per call.

Built on graph_traversal.reverse_requires_walk -- the same BFS primitive
Phase 4's blast_radius uses. blast_radius is this same traversal with no
blocked edges and the trace discarded; simulate_compromise is the general
case: it respects any blocks_propagation edges already in the graph, plus
an optional ad-hoc `blocked_edges` override for hypothetical mitigations
not yet persisted to Neo4j.
"""

from __future__ import annotations

import networkx as nx

from .graph_traversal import reverse_requires_walk
from .models import PackageKey


def simulate_compromise(
    graph: nx.DiGraph,
    start_package_key: PackageKey,
    blocked_edges: set[tuple[PackageKey, PackageKey]] | None = None,
) -> dict:
    """Simulate a supply-chain compromise starting at `start_package_key`.

    Propagates upward via REQUIRES edges (from a package to everything that
    requires it, directly or transitively), skipping any edge marked
    `blocks_propagation: true` in the graph, or listed in `blocked_edges`.

    Returns:
      compromised_packages: set[PackageKey] -- start_package_key plus every
        package reached by unblocked propagation.
      compromised_apps: set[str] -- every Application with a DEPENDS_ON
        edge to any package in compromised_packages (a direct lookup
        against existing edges, not a re-walk -- DEPENDS_ON already
        records a resolved fact, not a traversable path, so blocking
        doesn't apply at that boundary).
      trace: list[(PackageKey, PackageKey)] -- every REQUIRES edge actually
        crossed, as (dependent, dependency) tuples in the same direction
        the edge is stored in Neo4j, for a frontend to match against its
        rendered graph edges.
    """
    result = reverse_requires_walk(
        graph, start_package_key, blocked_edges=blocked_edges, respect_blocks_propagation=True,
    )
    return {
        "compromised_packages": result.compromised_packages,
        "compromised_apps": result.compromised_apps,
        "trace": result.trace,
    }
