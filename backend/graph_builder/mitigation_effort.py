"""Patch effort: classify how big a version jump is, using OSV's cached
'fixed' version data from Phase 3 -- no network, no live Neo4j.

Deliberately not a semver/PEP 440 parser: a plain split-on-'.' and compare
integer components. Real version strings with pre-release suffixes etc.
will fail to parse cleanly; that's treated the same as "no data" for effort
purposes (see classify_version_jump) rather than crashing.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .cache import MISSING, DiskCache
from .models import PackageKey
from .osv_client import package_cache_key

logger = logging.getLogger(__name__)

# effort scale: 1 = low (patch/later component only, or unparseable --
# documented simplification: unknown is treated as cheap, not expensive,
# since we'd rather under- than over-estimate effort for ranking purposes),
# 2 = medium (minor differs), 3 = high (major differs).
EFFORT_LOW = 1
EFFORT_MEDIUM = 2
EFFORT_HIGH = 3


def parse_version_tuple(version: str) -> tuple[int, ...] | None:
    """"1.2.3" -> (1, 2, 3). None if any component isn't a plain integer."""
    parts = version.split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def classify_version_jump(current: str, fixed: str) -> int:
    """EFFORT_HIGH if the major component differs, EFFORT_MEDIUM if only
    minor differs, EFFORT_LOW if only patch/later differs -- or if either
    version string can't be parsed as plain dot-separated integers at all."""
    current_t = parse_version_tuple(current)
    fixed_t = parse_version_tuple(fixed)
    if current_t is None or fixed_t is None:
        return EFFORT_LOW

    current_major = current_t[0] if current_t else 0
    fixed_major = fixed_t[0] if fixed_t else 0
    if current_major != fixed_major:
        return EFFORT_HIGH

    current_minor = current_t[1] if len(current_t) > 1 else 0
    fixed_minor = fixed_t[1] if len(fixed_t) > 1 else 0
    if current_minor != fixed_minor:
        return EFFORT_MEDIUM

    return EFFORT_LOW


def extract_fixed_versions(osv_vuln_detail: dict, package_name: str) -> list[str]:
    """All 'fixed' version strings from an OSV vuln detail's `affected`
    entries matching `package_name` (matched by name only -- an OSV
    advisory's affected entries are effectively always single-ecosystem, so
    this doesn't also cross-check ecosystem)."""
    fixed_versions = []
    for affected in osv_vuln_detail.get("affected") or []:
        if (affected.get("package") or {}).get("name") != package_name:
            continue
        for range_ in affected.get("ranges") or []:
            for event in range_.get("events") or []:
                if "fixed" in event:
                    fixed_versions.append(event["fixed"])
    return fixed_versions


def pick_target_fixed_version(candidates: list[str]) -> str | None:
    """The highest parseable candidate (patching to it clears every known
    fix cutoff); if none parse, just the first one -- still useful as a
    hint even though classify_version_jump will call it EFFORT_LOW
    ("unknown")."""
    if not candidates:
        return None
    parsed = [(c, parse_version_tuple(c)) for c in candidates]
    parseable = [(c, t) for c, t in parsed if t is not None]
    if not parseable:
        return candidates[0]
    return max(parseable, key=lambda ct: ct[1])[0]


def find_fixed_version_from_cache(
    package: PackageKey, osv_package_cache: DiskCache, osv_vuln_cache: DiskCache,
) -> str | None:
    """Reads Phase 3's already-cached OSV data (no network call) to find a
    target fixed version for `package`, or None if there isn't one cached
    (package was never enriched, or none of its vulns name a fix)."""
    stubs = osv_package_cache.get(package_cache_key(package))
    if stubs is MISSING or not stubs:
        return None

    candidates: list[str] = []
    for stub in stubs:
        detail = osv_vuln_cache.get(stub["id"])
        if detail is MISSING:
            continue
        candidates.extend(extract_fixed_versions(detail, package.name))

    return pick_target_fixed_version(candidates)
