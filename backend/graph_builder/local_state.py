"""Builds the same in-memory state `load_state_from_neo4j` builds, but
entirely from local files -- no Neo4j (and so no Docker) required.

Runs the exact same computation every other phase does (SBOM parsing,
merge, structural metrics via networkx, vulnerability enrichment,
risk scoring, mitigation ranking) directly in-process, reading
vulnerability data from the on-disk caches under `data/` instead of
Neo4j-persisted nodes. Those caches ship in the repo already warm for
the real dataset, so this needs zero network calls too -- it's meant as
a "clone and run" path for anyone who doesn't want to stand up Neo4j
just to see the app. `uvicorn graph_builder.api:app` still uses Neo4j by
default; set `NO_NEO4J=1` to use this instead (see README).
"""

from __future__ import annotations

from pathlib import Path

import networkx as nx

from .api_data import PackageApiData
from .cache import DiskCache
from .cyclonedx_parser import parse_sbom_file
from .enrichment import enrich_graph
from .epss_client import EpssClient
from .graph_merge import merge_apps
from .mitigation_effort import find_fixed_version_from_cache
from .mitigation_ranking import PackageMitigationInput, rank_mitigations
from .models import PackageKey
from .nvd_client import NvdClient
from .osv_client import OsvClient
from .risk_score import DEFAULT_WEIGHTS, compute_raw_factors, score_package
from .runtime_exposure import runtime_exposure_for_package
from .structural_metrics import compute_all_metrics


def load_state_from_local_files(
    sbom_dir: Path | str = "data/sbom",
    data_dir: Path | str = "data",
) -> tuple[nx.DiGraph, dict[PackageKey, PackageApiData], list[dict]]:
    sbom_dir = Path(sbom_dir)
    data_dir = Path(data_dir)

    parsed = [parse_sbom_file(p) for p in sorted(sbom_dir.glob("*.json"))]
    merged = merge_apps(parsed)
    total_apps = len(merged.applications)

    graph = nx.DiGraph()
    for app_id in merged.applications:
        graph.add_node(app_id, node_type="application")
    for pkg in merged.packages:
        graph.add_node(pkg, node_type="package", name=pkg.name, version=pkg.version, ecosystem=pkg.ecosystem)
    for (app_id, pkg), edge in merged.depends_on.items():
        graph.add_edge(app_id, pkg, edge_type="DEPENDS_ON", direct=edge.direct, depth=edge.depth)
    for src, tgt in merged.requires:
        graph.add_edge(src, tgt, edge_type="REQUIRES", blocks_propagation=None)

    metrics = compute_all_metrics(graph)

    osv_pkg_cache = DiskCache(data_dir / "osv_cache" / "packages")
    osv_vuln_cache = DiskCache(data_dir / "osv_cache" / "vulns")
    osv = OsvClient(osv_pkg_cache, osv_vuln_cache)
    nvd = NvdClient(DiskCache(data_dir / "nvd_cache"))
    epss = EpssClient(DiskCache(data_dir / "epss_cache"))
    vuln_graph = enrich_graph(merged, osv, nvd, epss)  # cache hits only if the shipped caches are warm

    package_data: dict[PackageKey, PackageApiData] = {}
    mitigation_inputs: list[PackageMitigationInput] = []
    for pkg in merged.packages:
        m = metrics[pkg]
        vulns_detail = [
            {
                "id": vuln_graph.vulnerabilities[vid].vuln_id,
                "id_type": vuln_graph.vulnerabilities[vid].id_type,
                "cvss_score": vuln_graph.vulnerabilities[vid].cvss_score,
                "cvss_severity": vuln_graph.vulnerabilities[vid].cvss_severity,
                "cvss_source": vuln_graph.vulnerabilities[vid].cvss_source,
                "epss_score": vuln_graph.vulnerabilities[vid].epss_score,
                "epss_percentile": vuln_graph.vulnerabilities[vid].epss_percentile,
            }
            for (p, vid) in vuln_graph.affected_by
            if p == pkg
        ]
        vulns_agg = [{"cvss_score": v["cvss_score"], "epss_score": v["epss_score"]} for v in vulns_detail]
        exposure = runtime_exposure_for_package(m.blast_radius_apps)
        raw = compute_raw_factors(
            vulnerabilities=vulns_agg,
            betweenness_centrality=m.betweenness_centrality,
            blast_radius_apps=m.blast_radius_apps,
            total_apps=total_apps,
            runtime_exposure=exposure,
        )
        scored = score_package(raw, DEFAULT_WEIGHTS)

        graph.nodes[pkg].update({
            "risk_score": scored["risk_score"],
            "fan_in": m.fan_in,
            "betweenness_centrality": m.betweenness_centrality,
        })
        package_data[pkg] = PackageApiData(
            package=pkg,
            fan_in=m.fan_in,
            depth=m.depth,
            betweenness_centrality=m.betweenness_centrality,
            blast_radius_apps=m.blast_radius_apps,
            raw_factors=raw,
            weighted_terms=scored["weighted_terms"],
            risk_score=scored["risk_score"],
            vulnerabilities=vulns_detail,
        )
        if vulns_agg:
            fixed_version = find_fixed_version_from_cache(pkg, osv_pkg_cache, osv_vuln_cache)
            mitigation_inputs.append(PackageMitigationInput(
                package=pkg,
                raw_factors=raw,
                vulnerabilities=vulns_agg,
                blast_radius_apps=m.blast_radius_apps,
                total_apps=total_apps,
                fixed_version=fixed_version,
            ))

    mitigations = rank_mitigations(mitigation_inputs, DEFAULT_WEIGHTS)
    return graph, package_data, mitigations
