"""The mandatory shared-package sanity checks.

If these fail, nothing downstream (vulnerability enrichment, blast-radius
simulation) will demo correctly, so failures raise with a specific diagnosis
rather than a bare assert.
"""

from __future__ import annotations

from .models import Graph, PackageKey
from .queries import apps_depending_on


class SanityCheckError(Exception):
    """A shared-package fan-in check failed, with a specific diagnosis."""


def check_shared_package(
    graph: Graph,
    name: str,
    version: str,
    ecosystem: str,
    expected_apps: list[str],
) -> None:
    """Assert `name@version` (ecosystem) is one Package node depended on by
    every app in `expected_apps`.

    Raises SanityCheckError with a diagnosis distinguishing "not found at
    all" (likely a version-string or ecosystem mismatch) from "found but
    fan-in too low" (the pin didn't land in every manifest it should have).
    """
    key = PackageKey(name=name, version=version, ecosystem=ecosystem)

    if key not in graph.packages:
        raise SanityCheckError(
            f"{name}@{version} ({ecosystem}) not found as a Package node in "
            f"the merged graph — check for a version-string mismatch (e.g. "
            f"an unpinned/floating version resolving differently per app) or "
            f"an ecosystem/purl-type mismatch between SBOMs."
        )

    depending_apps = apps_depending_on(graph, name, version, ecosystem)
    missing = sorted(set(expected_apps) - set(depending_apps))

    if missing:
        raise SanityCheckError(
            f"{name}@{version} ({ecosystem}) found but fan-in too low: "
            f"{len(depending_apps)} incoming DEPENDS_ON edge(s) from "
            f"{depending_apps}, expected edges from all of "
            f"{sorted(expected_apps)} (missing: {missing}). Check that the "
            f"pin actually landed in {missing}'s manifest and that its SBOM "
            f"was (re)generated after pinning."
        )
