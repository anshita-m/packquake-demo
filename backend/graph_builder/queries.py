"""Read-only query helpers over an in-memory Graph object (pre-Neo4j).

These operate on the same Graph that graph_merge.merge_apps produces, so
they're useful both as a debugging tool and as the thing the mandatory
sanity check is built on top of.
"""

from __future__ import annotations

from .models import Graph, PackageKey, VulnGraph


def apps_depending_on(graph: Graph, name: str, version: str, ecosystem: str) -> list[str]:
    """Which apps have a DEPENDS_ON edge (direct or transitive) to this package?"""
    key = PackageKey(name=name, version=version, ecosystem=ecosystem)
    return sorted(app_id for (app_id, pkg) in graph.depends_on if pkg == key)


def package_node_count(graph: Graph, name: str, version: str, ecosystem: str) -> int:
    """How many distinct Package nodes exist for this (name, version, ecosystem)?

    Should always be 0 or 1 -- PackageKey equality/hashing on
    (name, version, ecosystem) is exactly what makes graph.packages a set
    instead of a list, so a well-formed graph can never have more than one.
    """
    key = PackageKey(name=name, version=version, ecosystem=ecosystem)
    return 1 if key in graph.packages else 0


def vulnerabilities_for_package(vuln_graph: VulnGraph, package: PackageKey) -> list:
    """All Vulnerability records a given package is AFFECTED_BY."""
    vuln_ids = [vid for (pkg, vid) in vuln_graph.affected_by if pkg == package]
    return [vuln_graph.vulnerabilities[vid] for vid in vuln_ids]


def vulnerabilities_for_app(graph: Graph, vuln_graph: VulnGraph, app_id: str) -> dict[PackageKey, list]:
    """{package: [Vulnerability, ...]} for every package the given app
    depends on (direct or transitive) that has at least one known vuln."""
    app_packages = [pkg for (aid, pkg) in graph.depends_on if aid == app_id]
    result = {}
    for pkg in app_packages:
        vulns = vulnerabilities_for_package(vuln_graph, pkg)
        if vulns:
            result[pkg] = vulns
    return result
