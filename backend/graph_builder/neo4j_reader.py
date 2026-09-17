"""Reads the current graph OUT of Neo4j and builds an in-memory
networkx.DiGraph from it.

This is deliberately a fresh read path, separate from Phase 2's
cyclonedx_parser/graph_merge (which build a Graph by re-parsing SBOM files).
Phase 4's structural metrics operate on whatever is actually persisted in
Neo4j right now, not on a re-derivation from local SBOMs.

Node/edge shape of the returned graph:
  - Application nodes: node id is the app_id string, `node_type="application"`.
  - Package nodes: node id is a PackageKey, `node_type="package"` plus
    name/version/ecosystem attributes.
  - Application -> Package edges: `edge_type="DEPENDS_ON"`, plus `direct`
    and `depth` attributes (copied straight from the relationship).
  - Package -> Package edges: `edge_type="REQUIRES"`, plus a
    `blocks_propagation` attribute (None if the property was never set in
    Neo4j -- callers should treat that the same as False, not require it).
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from .models import PackageKey


def read_graph_from_neo4j(driver: Any) -> nx.DiGraph:
    graph = nx.DiGraph()

    with driver.session() as session:
        for record in session.run("MATCH (a:Application) RETURN a.app_id AS app_id"):
            graph.add_node(record["app_id"], node_type="application")

        for record in session.run(
            "MATCH (p:Package) RETURN p.name AS name, p.version AS version, p.ecosystem AS ecosystem"
        ):
            key = PackageKey(record["name"], record["version"], record["ecosystem"])
            graph.add_node(key, node_type="package", name=key.name, version=key.version, ecosystem=key.ecosystem)

        for record in session.run(
            "MATCH (a:Application)-[r:DEPENDS_ON]->(p:Package) "
            "RETURN a.app_id AS app_id, p.name AS name, p.version AS version, "
            "p.ecosystem AS ecosystem, r.direct AS direct, r.depth AS depth"
        ):
            key = PackageKey(record["name"], record["version"], record["ecosystem"])
            graph.add_edge(
                record["app_id"], key, edge_type="DEPENDS_ON", direct=record["direct"], depth=record["depth"],
            )

        for record in session.run(
            "MATCH (p1:Package)-[r:REQUIRES]->(p2:Package) "
            "RETURN p1.name AS n1, p1.version AS v1, p1.ecosystem AS e1, "
            "p2.name AS n2, p2.version AS v2, p2.ecosystem AS e2, "
            "r.blocks_propagation AS blocks_propagation"
        ):
            src = PackageKey(record["n1"], record["v1"], record["e1"])
            tgt = PackageKey(record["n2"], record["v2"], record["e2"])
            graph.add_edge(
                src, tgt, edge_type="REQUIRES", blocks_propagation=record.get("blocks_propagation"),
            )

    return graph
