"""Exercises `load_state_from_local_files` (the NO_NEO4J=1 code path) end to
end against the real dataset. Everything it reads --SBOMs and the OSV/NVD/
EPSS caches-- ships in the repo already warm, so this makes zero network
calls; skips cleanly if the cache isn't warm for some reason.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from graph_builder.cache import MISSING, DiskCache
from graph_builder.local_state import load_state_from_local_files
from graph_builder.models import PackageKey
from graph_builder.osv_client import package_cache_key

REPO_ROOT = Path(__file__).resolve().parents[2]
WERKZEUG = PackageKey("werkzeug", "0.15.2", "pypi")


def test_builds_full_state_from_local_files_only():
    osv_pkg_cache = DiskCache(REPO_ROOT / "data" / "osv_cache" / "packages", name="osv-package")
    if osv_pkg_cache.get(package_cache_key(WERKZEUG)) is MISSING:
        pytest.skip("OSV cache not warm for the real dataset -- run an enrichment pass first")

    graph, package_data, mitigations = load_state_from_local_files(
        sbom_dir=REPO_ROOT / "data" / "sbom",
        data_dir=REPO_ROOT / "data",
    )

    app_nodes = [n for n, d in graph.nodes(data=True) if d.get("node_type") == "application"]
    assert sorted(app_nodes) == ["flack", "hackathon-starter", "microblog", "node-realworld"]
    assert len(package_data) > 500  # the real graph has ~628 packages

    # Every package_data entry should carry a computed risk_score, not just
    # the ones with known CVEs -- structural factors alone still score.
    assert all(data.risk_score is not None for data in package_data.values())

    assert mitigations, "expected at least one vulnerable package in the ranking"
    assert any(m["package"]["name"] == "werkzeug" for m in mitigations)
