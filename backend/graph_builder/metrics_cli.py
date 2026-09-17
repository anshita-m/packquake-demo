"""CLI entry point for Phase 4:
python -m graph_builder.metrics_cli [--neo4j-uri ...] [--dry-run]

Reads the current graph out of Neo4j, computes fan_in/depth/
betweenness_centrality/blast_radius_apps for every Package, writes them
back, and prints a verification summary for the real, naturally-shared
package (accepts@1.3.8 -- see cli.py's SANITY_CHECKS comment for why
there's no Python-side equivalent right now) so "non-trivial, correct
values" is directly checkable from the CLI output.
"""

from __future__ import annotations

import argparse
import os
import sys

from .models import PackageKey
from .neo4j_metrics_writer import Neo4jMetricsWriter
from .neo4j_reader import read_graph_from_neo4j
from .structural_metrics import compute_all_metrics

SPOTLIGHT_PACKAGES = [
    PackageKey("accepts", "1.3.8", "npm"),
]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m graph_builder.metrics_cli",
        description="Compute structural metrics for every Package node in Neo4j and write them back.",
    )
    parser.add_argument("--neo4j-uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    parser.add_argument("--neo4j-user", default=os.environ.get("NEO4J_USER", "neo4j"))
    parser.add_argument("--neo4j-password", default=os.environ.get("NEO4J_PASSWORD", "password"))
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--dry-run", action="store_true", help="Compute and print metrics but don't write them back.")
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))
    try:
        graph = read_graph_from_neo4j(driver)
        n_apps = sum(1 for _n, d in graph.nodes(data=True) if d.get("node_type") == "application")
        n_pkgs = sum(1 for _n, d in graph.nodes(data=True) if d.get("node_type") == "package")
        n_depends_on = sum(1 for _u, _v, d in graph.edges(data=True) if d.get("edge_type") == "DEPENDS_ON")
        n_requires = sum(1 for _u, _v, d in graph.edges(data=True) if d.get("edge_type") == "REQUIRES")
        print(f"Read from Neo4j: {n_apps} apps, {n_pkgs} packages, {n_depends_on} DEPENDS_ON, {n_requires} REQUIRES")

        if n_pkgs == 0:
            print("No Package nodes found -- run Phase 2's --load-neo4j first.", file=sys.stderr)
            return 1

        metrics = compute_all_metrics(graph)
        print(f"Computed metrics for {len(metrics)} packages")

        if not args.dry_run:
            Neo4jMetricsWriter(driver, batch_size=args.batch_size).write_metrics(metrics)
            print(f"Wrote fan_in/depth/betweenness_centrality/blast_radius_apps onto {len(metrics)} Package nodes")

        print()
        print("=== naturally-shared packages ===")
        for pkg in SPOTLIGHT_PACKAGES:
            m = metrics.get(pkg)
            if m is None:
                print(f"  {pkg.name}@{pkg.version} ({pkg.ecosystem}): NOT FOUND IN GRAPH")
                continue
            print(
                f"  {pkg.name}@{pkg.version} ({pkg.ecosystem}): fan_in={m.fan_in} depth={m.depth} "
                f"centrality={m.betweenness_centrality:.4f} blast_radius_apps={m.blast_radius_apps}"
            )

        return 0
    finally:
        driver.close()


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
