"""Merge per-app parse results into a single shared, deduplicated Graph."""

from __future__ import annotations

from .models import Graph, ParsedApp


def merge_apps(parsed_apps: list[ParsedApp]) -> Graph:
    graph = Graph()

    for app in parsed_apps:
        graph.applications.add(app.app_id)

        for edge in app.depends_on:
            graph.packages.add(edge.package)
            key = (app.app_id, edge.package)
            existing = graph.depends_on.get(key)
            # Same (app, package) can appear twice if two distinct bom-refs in
            # one document resolved to the same PackageKey; keep the shortest.
            if existing is None or edge.depth < existing.depth:
                graph.depends_on[key] = edge

        for req in app.requires:
            graph.packages.add(req.source)
            graph.packages.add(req.target)
            graph.requires.add((req.source, req.target))

    return graph
