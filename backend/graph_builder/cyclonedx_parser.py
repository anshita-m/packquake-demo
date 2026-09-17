"""Parse a single CycloneDX SBOM document into a ParsedApp.

Key rule: bom-ref strings are only meaningful *within one document*. We
resolve every bom-ref to a global (name, version, ecosystem) PackageKey using
that document's own `components` array before doing anything else, and only
ever use raw bom-refs to walk that one document's `dependencies` graph.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict, deque
from pathlib import Path

from .models import DependsOnEdge, ParsedApp, PackageKey, RequiresEdge
from .purl import parse_purl

logger = logging.getLogger(__name__)


class SbomParseError(Exception):
    """Raised when a document is missing something we cannot recover from."""


def parse_sbom_file(path: Path) -> ParsedApp:
    """Parse a CycloneDX JSON file. The app_id is taken from the filename stem."""
    path = Path(path)
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    return parse_sbom_document(doc, app_id=path.stem)


def parse_sbom_document(doc: dict, app_id: str) -> ParsedApp:
    root_ref = _get_root_ref(doc, app_id)
    ref_to_key = _build_ref_to_key(doc.get("components") or [], app_id)
    adjacency = _build_adjacency(doc, root_ref, ref_to_key, app_id)
    depths = _bfs_depths(root_ref, adjacency)

    depends_on_edges = _build_depends_on_edges(app_id, root_ref, ref_to_key, depths)
    requires_edges = _build_requires_edges(app_id, root_ref, ref_to_key, adjacency)

    return ParsedApp(app_id=app_id, depends_on=depends_on_edges, requires=requires_edges)


def _get_root_ref(doc: dict, app_id: str) -> str:
    metadata = doc.get("metadata") or {}
    root_component = metadata.get("component")
    if not root_component or not root_component.get("bom-ref"):
        raise SbomParseError(
            f"[{app_id}] SBOM has no metadata.component.bom-ref; cannot "
            "establish a root to compute direct/depth from."
        )
    return root_component["bom-ref"]


def _build_ref_to_key(components: list[dict], app_id: str) -> dict[str, PackageKey]:
    ref_to_key: dict[str, PackageKey] = {}
    for comp in components:
        ref = comp.get("bom-ref")
        if not ref:
            continue
        key = _component_to_key(comp, app_id)
        if key is not None:
            ref_to_key[ref] = key
    return ref_to_key


def _component_to_key(comp: dict, app_id: str) -> PackageKey | None:
    purl = comp.get("purl")
    name = comp.get("name")
    version = comp.get("version") or ""

    if purl:
        try:
            ecosystem, purl_name, purl_version = parse_purl(purl)
            return PackageKey(
                name=purl_name or name or "",
                version=purl_version or version,
                ecosystem=ecosystem,
            )
        except ValueError:
            logger.warning(
                "[%s] could not parse purl %r for component %r; falling back "
                "to the component's declared type as ecosystem.",
                app_id, purl, name,
            )

    if not name:
        logger.warning("[%s] component with bom-ref %r has no name; skipping.", app_id, comp.get("bom-ref"))
        return None

    ecosystem = comp.get("type") or "unknown"
    return PackageKey(name=name, version=version, ecosystem=ecosystem)


def _build_adjacency(
    doc: dict, root_ref: str, ref_to_key: dict[str, PackageKey], app_id: str
) -> dict[str, set[str]]:
    adjacency: dict[str, set[str]] = defaultdict(set)

    if "dependencies" not in doc or doc["dependencies"] is None:
        logger.warning(
            "[%s] SBOM has no 'dependencies' array; treating all %d "
            "components as direct depth-1 dependencies of the root.",
            app_id, len(ref_to_key),
        )
        adjacency[root_ref].update(ref_to_key.keys())
        return adjacency

    for dep in doc["dependencies"]:
        ref = dep.get("ref")
        if not ref:
            continue
        depends_on = dep.get("dependsOn") or []
        # A ref can appear more than once in the array; merge, don't overwrite.
        adjacency[ref].update(depends_on)

    # Some real scanners (observed: Syft directory scans of npm projects)
    # populate a full, non-empty component-to-component dependency graph but
    # never link the root to anything -- the root's own bom-ref simply never
    # appears as a `ref`. Distinct from an explicitly empty `dependencies`
    # array (which legitimately means "zero dependencies" and must NOT
    # trigger this). When it happens, we have no signal for direct vs.
    # transitive, so fall back the same way as a missing array: treat every
    # component as a direct depth-1 dependency of the root. The REQUIRES
    # edges captured among the components themselves are untouched and used
    # as-is -- only the root's own linkage was missing.
    if doc["dependencies"] and root_ref not in adjacency:
        logger.warning(
            "[%s] SBOM has a non-empty 'dependencies' array but the root "
            "(%r) is never listed as a dependent; treating all %d "
            "components as direct depth-1 dependencies of the root instead.",
            app_id, root_ref, len(ref_to_key),
        )
        adjacency[root_ref].update(ref_to_key.keys())

    return adjacency


def _bfs_depths(root_ref: str, adjacency: dict[str, set[str]]) -> dict[str, int]:
    """Shortest-path depth from root_ref to every reachable ref."""
    depths = {root_ref: 0}
    queue: deque[str] = deque([root_ref])
    while queue:
        current = queue.popleft()
        for neighbor in adjacency.get(current, ()):
            if neighbor not in depths:
                depths[neighbor] = depths[current] + 1
                queue.append(neighbor)
    return depths


def _build_depends_on_edges(
    app_id: str,
    root_ref: str,
    ref_to_key: dict[str, PackageKey],
    depths: dict[str, int],
) -> list[DependsOnEdge]:
    edges = []
    for ref, depth in depths.items():
        if ref == root_ref:
            continue
        key = ref_to_key.get(ref)
        if key is None:
            logger.warning(
                "[%s] dependency ref %r is reachable but has no matching "
                "component entry; skipping.", app_id, ref,
            )
            continue
        edges.append(DependsOnEdge(app_id=app_id, package=key, direct=(depth == 1), depth=depth))
    return edges


def _build_requires_edges(
    app_id: str,
    root_ref: str,
    ref_to_key: dict[str, PackageKey],
    adjacency: dict[str, set[str]],
) -> list[RequiresEdge]:
    edges = []
    for ref, targets in adjacency.items():
        if ref == root_ref:
            continue  # root's edges are DEPENDS_ON, not REQUIRES
        src_key = ref_to_key.get(ref)
        if src_key is None:
            continue
        for target_ref in targets:
            tgt_key = ref_to_key.get(target_ref)
            if tgt_key is None:
                logger.warning(
                    "[%s] dependency edge %r -> %r has no matching target "
                    "component; skipping.", app_id, ref, target_ref,
                )
                continue
            if src_key == tgt_key:
                continue
            edges.append(RequiresEdge(source=src_key, target=tgt_key))
    return edges
