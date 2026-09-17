"""Phase 7 spec's required test 5: run the full pipeline (parse -> Phase 4
metrics -> Phase 3 vuln data -> Phase 6 factors -> Phase 7 ranking) against
the real graph and confirm at least one of flack's known-old pins (Werkzeug
0.15.2, Jinja2 2.10.1, itsdangerous 0.24, ...) shows up meaningfully.

Reuses Phase 3's own enrich_graph against the real on-disk OSV/NVD/EPSS
caches (populated by a separate live run against flack's 46 packages) --
since flack's data is already cached, this makes zero network calls, but
still exercises the real CVE data end to end rather than synthetic fixtures.
Skips cleanly if that cache isn't warm.
"""

from __future__ import annotations

from pathlib import Path

import networkx as nx
import pytest

from graph_builder.cache import MISSING, DiskCache
from graph_builder.cyclonedx_parser import parse_sbom_file
from graph_builder.enrichment import enrich_graph
from graph_builder.epss_client import EpssClient
from graph_builder.graph_merge import merge_apps
from graph_builder.mitigation_effort import find_fixed_version_from_cache
from graph_builder.mitigation_ranking import PackageMitigationInput, rank_mitigations
from graph_builder.models import Graph, PackageKey
from graph_builder.nvd_client import NvdClient
from graph_builder.osv_client import OsvClient, package_cache_key
from graph_builder.risk_score import DEFAULT_WEIGHTS, compute_raw_factors
from graph_builder.runtime_exposure import runtime_exposure_for_package
from graph_builder.structural_metrics import compute_all_metrics

REPO_ROOT = Path(__file__).resolve().parents[2]
WERKZEUG = PackageKey("werkzeug", "0.15.2", "pypi")


def _build_networkx_graph(merged: Graph) -> nx.DiGraph:
    g = nx.DiGraph()
    for app_id in merged.applications:
        g.add_node(app_id, node_type="application")
    for pkg in merged.packages:
        g.add_node(pkg, node_type="package", name=pkg.name, version=pkg.version, ecosystem=pkg.ecosystem)
    for (app_id, pkg), edge in merged.depends_on.items():
        g.add_edge(app_id, pkg, edge_type="DEPENDS_ON", direct=edge.direct, depth=edge.depth)
    for (src, tgt) in merged.requires:
        g.add_edge(src, tgt, edge_type="REQUIRES")
    return g


def test_flack_old_pins_show_up_meaningfully_in_mitigation_ranking():
    sbom_dir = REPO_ROOT / "data" / "sbom"
    osv_pkg_cache = DiskCache(REPO_ROOT / "data" / "osv_cache" / "packages", name="osv-package")
    osv_vuln_cache = DiskCache(REPO_ROOT / "data" / "osv_cache" / "vulns", name="osv-vuln")

    if osv_pkg_cache.get(package_cache_key(WERKZEUG)) is MISSING:
        pytest.skip("OSV cache not warm for flack's packages -- run a Phase 3 enrichment pass over flack first")

    parsed_apps = [parse_sbom_file(p) for p in sorted(sbom_dir.glob("*.json"))]
    merged = merge_apps(parsed_apps)
    total_apps = len(merged.applications)
    graph = _build_networkx_graph(merged)
    metrics = compute_all_metrics(graph)

    # flack's packages only -- everything here should already be cached from
    # the earlier targeted enrichment run, so this makes zero network calls.
    flack_packages = {pkg for (app_id, pkg) in merged.depends_on if app_id == "flack"}
    scoped = Graph(applications={"flack"}, packages=flack_packages)
    osv = OsvClient(osv_pkg_cache, osv_vuln_cache)
    nvd = NvdClient(DiskCache(REPO_ROOT / "data" / "nvd_cache", name="nvd"))
    epss = EpssClient(DiskCache(REPO_ROOT / "data" / "epss_cache", name="epss"))
    vuln_graph = enrich_graph(scoped, osv, nvd, epss)

    assert osv_pkg_cache.stats.misses == 0 and osv_vuln_cache.stats.misses == 0, (
        "expected an all-cache-hit run; a miss means this test made a live network call"
    )

    mitigation_inputs = []
    for pkg in flack_packages:
        pkg_vulns = [
            {"cvss_score": vuln_graph.vulnerabilities[vid].cvss_score, "epss_score": vuln_graph.vulnerabilities[vid].epss_score}
            for (p, vid) in vuln_graph.affected_by
            if p == pkg
        ]
        if not pkg_vulns:
            continue
        m = metrics[pkg]
        exposure = runtime_exposure_for_package(m.blast_radius_apps)
        raw = compute_raw_factors(
            vulnerabilities=pkg_vulns, betweenness_centrality=m.betweenness_centrality,
            blast_radius_apps=m.blast_radius_apps, total_apps=total_apps, runtime_exposure=exposure,
        )
        fixed_version = find_fixed_version_from_cache(pkg, osv_pkg_cache, osv_vuln_cache)
        mitigation_inputs.append(PackageMitigationInput(
            package=pkg, raw_factors=raw, vulnerabilities=pkg_vulns,
            blast_radius_apps=m.blast_radius_apps, total_apps=total_apps, fixed_version=fixed_version,
        ))

    ranked = rank_mitigations(mitigation_inputs, DEFAULT_WEIGHTS)
    assert ranked, "expected at least one vulnerable flack package in the ranking"

    werkzeug_entries = [e for e in ranked if e["package"]["name"] == "werkzeug"]
    assert werkzeug_entries, "expected werkzeug@0.15.2 (a real, known-old pin) to appear in the ranking"

    entry = werkzeug_entries[0]
    assert entry["risk_reduction"] > 0
    assert entry["explanation"]
    print(f"\nwerkzeug@0.15.2 ranked #{ranked.index(entry) + 1} of {len(ranked)}: {entry['explanation']}")
    print(f"  risk_score {entry['risk_score_before']:.4f} -> {entry['risk_score_after']:.4f}, "
          f"priority={entry['priority']:.4f}, effort={entry['effort']}, fixed_version={entry['fixed_version']}")
