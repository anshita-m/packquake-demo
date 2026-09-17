"""Plain data structures for the parsed dependency graph.

Deliberately framework/DB-free so the parsing and merge logic (graph_merge.py,
cyclonedx_parser.py, sanity_checks.py) is testable with plain pytest and no
Neo4j driver in scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PackageKey:
    """The global dedup key for a Package node: (name, version, ecosystem)."""

    name: str
    version: str
    ecosystem: str


@dataclass(frozen=True)
class DependsOnEdge:
    """An Application -DEPENDS_ON-> Package edge."""

    app_id: str
    package: PackageKey
    direct: bool
    depth: int


@dataclass(frozen=True)
class RequiresEdge:
    """A Package -REQUIRES-> Package edge (transitive chain within one app's SBOM)."""

    source: PackageKey
    target: PackageKey


@dataclass
class ParsedApp:
    """The result of parsing a single SBOM document, before merging."""

    app_id: str
    depends_on: list[DependsOnEdge] = field(default_factory=list)
    requires: list[RequiresEdge] = field(default_factory=list)


@dataclass
class Graph:
    """The merged, deduplicated graph across all parsed applications."""

    applications: set[str] = field(default_factory=set)
    packages: set[PackageKey] = field(default_factory=set)
    depends_on: dict[tuple[str, PackageKey], DependsOnEdge] = field(default_factory=dict)
    requires: set[tuple[PackageKey, PackageKey]] = field(default_factory=set)


@dataclass(frozen=True)
class Vulnerability:
    """A Vulnerability node. `vuln_id` is the Neo4j MERGE key: a CVE id when
    one is aliased, otherwise a GHSA id (OSV/GHSA advisories don't always
    have a CVE)."""

    vuln_id: str
    id_type: str  # "cve" | "ghsa"
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_source: str | None = None  # "osv" | "nvd" | None
    epss_score: float | None = None
    epss_percentile: float | None = None


@dataclass
class VulnGraph:
    """Package -AFFECTED_BY-> Vulnerability, keyed the same way Graph keys
    Application -DEPENDS_ON-> Package."""

    vulnerabilities: dict[str, Vulnerability] = field(default_factory=dict)
    affected_by: set[tuple[PackageKey, str]] = field(default_factory=set)
