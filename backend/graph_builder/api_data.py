"""Builds everything the API needs, once, from Neo4j.

Deliberately does NOT modify neo4j_reader.py, structural_metrics.py, or any
earlier-phase module -- this reads Phase 4/6's already-computed Package
properties directly (same pattern Phase 7's neo4j_risk_reader.
read_packages_for_mitigation already uses) and merges them onto the
networkx graph read_graph_from_neo4j (Phase 4, untouched) already builds,
as extra node attributes. Adding attributes to existing nodes is additive
and doesn't change what any earlier-phase consumer of that graph sees.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from .models import PackageKey
from .neo4j_reader import read_graph_from_neo4j
from .risk_score import RAW_FACTOR_NAMES

_SCORE_PROPERTY_NAMES = (
    "fan_in", "depth", "betweenness_centrality", "blast_radius_apps",
    *RAW_FACTOR_NAMES,
    *(f"weighted_{name}" for name in RAW_FACTOR_NAMES),
    "risk_score",
)


@dataclass
class PackageApiData:
    package: PackageKey
    fan_in: int | None = None
    depth: int | None = None
    betweenness_centrality: float | None = None
    blast_radius_apps: list[str] = field(default_factory=list)
    raw_factors: dict[str, float] | None = None
    weighted_terms: dict[str, float] | None = None
    risk_score: float | None = None
    vulnerabilities: list[dict] = field(default_factory=list)  # full detail, not aggregated


def _read_package_api_data(driver: Any) -> dict[PackageKey, PackageApiData]:
    score_select = ", ".join(f"p.{name} AS {name}" for name in _SCORE_PROPERTY_NAMES)
    query = (
        "MATCH (p:Package) "
        "OPTIONAL MATCH (p)-[:AFFECTED_BY]->(v:Vulnerability) "
        "WITH p, collect(CASE WHEN v IS NULL THEN NULL ELSE {"
        "id: v.vuln_id, id_type: v.id_type, cvss_score: v.cvss_score, "
        "cvss_severity: v.cvss_severity, cvss_source: v.cvss_source, "
        "epss_score: v.epss_score, epss_percentile: v.epss_percentile"
        "} END) AS raw_vulns "
        "RETURN p.name AS name, p.version AS version, p.ecosystem AS ecosystem, "
        f"{score_select}, "
        "[v IN raw_vulns WHERE v IS NOT NULL] AS vulnerabilities"
    )

    results: dict[PackageKey, PackageApiData] = {}
    with driver.session() as session:
        for record in session.run(query):
            pkg = PackageKey(record["name"], record["version"], record["ecosystem"])
            raw_factors = {name: record[name] for name in RAW_FACTOR_NAMES}
            if any(v is None for v in raw_factors.values()):
                raw_factors = None
            weighted_terms = {name: record[f"weighted_{name}"] for name in RAW_FACTOR_NAMES}
            if any(v is None for v in weighted_terms.values()):
                weighted_terms = None

            results[pkg] = PackageApiData(
                package=pkg,
                fan_in=record["fan_in"],
                depth=record["depth"],
                betweenness_centrality=record["betweenness_centrality"],
                blast_radius_apps=record["blast_radius_apps"] or [],
                raw_factors=raw_factors,
                weighted_terms=weighted_terms,
                risk_score=record["risk_score"],
                vulnerabilities=record["vulnerabilities"] or [],
            )
    return results


def build_app_graph(driver: Any) -> tuple[nx.DiGraph, dict[PackageKey, PackageApiData]]:
    """Returns (graph, package_data). `graph` is Phase 4's shape (Application/
    Package nodes, DEPENDS_ON/REQUIRES edges with their usual attributes)
    with fan_in/depth/betweenness_centrality/blast_radius_apps/risk_score
    additionally merged onto each Package node -- so simulate_compromise
    and GET /graph can both read from this one loaded-once object.
    `package_data` carries the fuller per-package detail (full raw/weighted
    factors, full vulnerability list) for GET /package/:id.
    """
    graph = read_graph_from_neo4j(driver)
    package_data = _read_package_api_data(driver)

    for pkg, data in package_data.items():
        if pkg not in graph:
            continue
        graph.nodes[pkg].update({
            "fan_in": data.fan_in,
            "depth": data.depth,
            "betweenness_centrality": data.betweenness_centrality,
            "blast_radius_apps": data.blast_radius_apps,
            "risk_score": data.risk_score,
        })

    return graph, package_data
