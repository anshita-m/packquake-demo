"""Reads what Phase 6 (and Phase 7) need out of Neo4j: per-package
betweenness_centrality + blast_radius_apps (already computed and stored by
Phase 4) plus each package's attached Vulnerability data (cvss_score/
epss_score, from Phase 3 if it has run), and the live Application count.

Unlike Phase 4's neo4j_reader, this doesn't need a full networkx graph --
Phase 6/7 only read already-computed Package properties and one hop out to
Vulnerability nodes, so a flat per-package structure is enough.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import PackageKey
from .risk_score import RAW_FACTOR_NAMES


@dataclass
class PackageRiskInput:
    package: PackageKey
    betweenness_centrality: float | None
    blast_radius_apps: list[str] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)  # [{"cvss_score": ..., "epss_score": ...}, ...]


@dataclass
class PackageMitigationRow:
    package: PackageKey
    raw_factors: dict[str, float] | None  # None if Phase 6 hasn't computed/stored these yet
    blast_radius_apps: list[str] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)


def read_total_apps(driver: Any) -> int:
    with driver.session() as session:
        record = session.run("MATCH (a:Application) RETURN count(a) AS n").single()
    return record["n"]


def read_packages_for_risk_scoring(driver: Any) -> list[PackageRiskInput]:
    query = (
        "MATCH (p:Package) "
        "OPTIONAL MATCH (p)-[:AFFECTED_BY]->(v:Vulnerability) "
        "WITH p, collect(CASE WHEN v IS NULL THEN NULL "
        "ELSE {cvss_score: v.cvss_score, epss_score: v.epss_score} END) AS raw_vulns "
        "RETURN p.name AS name, p.version AS version, p.ecosystem AS ecosystem, "
        "p.betweenness_centrality AS betweenness_centrality, "
        "p.blast_radius_apps AS blast_radius_apps, "
        "[v IN raw_vulns WHERE v IS NOT NULL] AS vulnerabilities"
    )
    results = []
    with driver.session() as session:
        for record in session.run(query):
            results.append(
                PackageRiskInput(
                    package=PackageKey(record["name"], record["version"], record["ecosystem"]),
                    betweenness_centrality=record["betweenness_centrality"],
                    blast_radius_apps=record["blast_radius_apps"] or [],
                    vulnerabilities=record["vulnerabilities"] or [],
                )
            )
    return results


def read_packages_for_mitigation(driver: Any) -> list[PackageMitigationRow]:
    """Reads the already-stored Phase 6 raw factors directly (no
    recomputation) plus AFFECTED_BY vulnerabilities and blast_radius_apps
    for Phase 7's explanation phrasing."""
    raw_factor_select = ", ".join(f"p.{name} AS {name}" for name in RAW_FACTOR_NAMES)
    query = (
        "MATCH (p:Package) "
        "OPTIONAL MATCH (p)-[:AFFECTED_BY]->(v:Vulnerability) "
        "WITH p, collect(CASE WHEN v IS NULL THEN NULL "
        "ELSE {cvss_score: v.cvss_score, epss_score: v.epss_score} END) AS raw_vulns "
        "RETURN p.name AS name, p.version AS version, p.ecosystem AS ecosystem, "
        f"{raw_factor_select}, "
        "p.blast_radius_apps AS blast_radius_apps, "
        "[v IN raw_vulns WHERE v IS NOT NULL] AS vulnerabilities"
    )
    results = []
    with driver.session() as session:
        for record in session.run(query):
            raw_values = {name: record[name] for name in RAW_FACTOR_NAMES}
            raw_factors = None if any(v is None for v in raw_values.values()) else raw_values
            results.append(
                PackageMitigationRow(
                    package=PackageKey(record["name"], record["version"], record["ecosystem"]),
                    raw_factors=raw_factors,
                    blast_radius_apps=record["blast_radius_apps"] or [],
                    vulnerabilities=record["vulnerabilities"] or [],
                )
            )
    return results
