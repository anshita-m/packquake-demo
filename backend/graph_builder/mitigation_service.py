"""Reusable Phase 7 orchestration: read from Neo4j + Phase 3's OSV cache,
build PackageMitigationInput rows, call rank_mitigations. Extracted out of
mitigation_cli.py so the API layer (Phase 8) can call the exact same logic
instead of re-implementing it -- both now just consume this.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .cache import DiskCache
from .mitigation_effort import find_fixed_version_from_cache
from .mitigation_ranking import PackageMitigationInput, rank_mitigations
from .neo4j_risk_reader import read_packages_for_mitigation, read_total_apps
from .risk_score import DEFAULT_WEIGHTS


def compute_ranked_mitigations(
    driver: Any,
    osv_cache_dir: str | Path = "data/osv_cache",
    weights: Mapping[str, float] = DEFAULT_WEIGHTS,
) -> tuple[list[dict], int, int]:
    """Returns (ranked mitigations, total packages read, packages skipped
    because Phase 6 hasn't computed raw factors for them yet)."""
    total_apps = read_total_apps(driver)
    rows = read_packages_for_mitigation(driver)

    osv_package_cache = DiskCache(Path(osv_cache_dir) / "packages", name="osv-package")
    osv_vuln_cache = DiskCache(Path(osv_cache_dir) / "vulns", name="osv-vuln")

    skipped_no_phase6 = 0
    mitigation_inputs = []
    for row in rows:
        if not row.vulnerabilities:
            continue
        if row.raw_factors is None:
            skipped_no_phase6 += 1
            continue
        fixed_version = find_fixed_version_from_cache(row.package, osv_package_cache, osv_vuln_cache)
        mitigation_inputs.append(PackageMitigationInput(
            package=row.package,
            raw_factors=row.raw_factors,
            vulnerabilities=row.vulnerabilities,
            blast_radius_apps=row.blast_radius_apps,
            total_apps=total_apps,
            fixed_version=fixed_version,
        ))

    ranked = rank_mitigations(mitigation_inputs, weights)
    return ranked, len(rows), skipped_no_phase6
