"""Thin helpers to set/query `blocks_propagation` on a REQUIRES edge in
Neo4j.

v1, per the plan: manually settable for the demo (e.g. "this package pins
an incompatible exact version, so a compromise of its dependency can't
actually reach it"). No automatic version-compatibility detection yet --
that's explicitly later-if-time-allows.
"""

from __future__ import annotations

from typing import Any

from .models import PackageKey

_MATCH_REQUIRES_EDGE = (
    "MATCH (dependent:Package {name: $dn, version: $dv, ecosystem: $de})"
    "-[r:REQUIRES]->"
    "(dependency:Package {name: $en, version: $ev, ecosystem: $ee}) "
)


def _edge_params(dependent: PackageKey, dependency: PackageKey) -> dict:
    return {
        "dn": dependent.name, "dv": dependent.version, "de": dependent.ecosystem,
        "en": dependency.name, "ev": dependency.version, "ee": dependency.ecosystem,
    }


def set_blocks_propagation(driver: Any, dependent: PackageKey, dependency: PackageKey, blocks: bool) -> None:
    """Set (or clear) blocks_propagation on the REQUIRES edge
    dependent -> dependency. Raises ValueError if no such edge exists."""
    query = _MATCH_REQUIRES_EDGE + "SET r.blocks_propagation = $blocks RETURN r"
    with driver.session() as session:
        result = session.run(query, blocks=blocks, **_edge_params(dependent, dependency))
        if result.single() is None:
            raise ValueError(f"no REQUIRES edge from {dependent} to {dependency}")


def get_blocks_propagation(driver: Any, dependent: PackageKey, dependency: PackageKey) -> bool:
    """Current blocks_propagation value for dependent -> dependency
    (False if unset). Raises ValueError if no such edge exists."""
    query = _MATCH_REQUIRES_EDGE + "RETURN r.blocks_propagation AS blocks_propagation"
    with driver.session() as session:
        record = session.run(query, **_edge_params(dependent, dependency)).single()
    if record is None:
        raise ValueError(f"no REQUIRES edge from {dependent} to {dependency}")
    return bool(record["blocks_propagation"])
