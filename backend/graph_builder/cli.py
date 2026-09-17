"""CLI entry point: python -m graph_builder.cli --sbom-dir data/sbom [--load-neo4j]"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .cyclonedx_parser import SbomParseError, parse_sbom_file
from .graph_merge import merge_apps
from .sanity_checks import SanityCheckError, check_shared_package

# These check real, naturally-shared packages in the actual Syft-scanned
# data (data/sbom/), not planted ones -- accepts@1.3.8 is a real transitive
# dependency both Express apps pull in independently. There's currently no
# equivalent for the two Python apps: microblog and flack's real pins don't
# share a single (name, version) pair (e.g. microblog has requests==2.31.0,
# flack has requests==2.9.1 -- different versions, so they dedup to two
# separate Package nodes, not one). That's a known gap, not a bug -- if you
# want a Python-side check too, pin a shared version in both apps' real
# manifests and re-run syft.
SANITY_CHECKS = [
    {
        "name": "accepts",
        "version": "1.3.8",
        "ecosystem": "npm",
        "expected_apps": ["hackathon-starter", "node-realworld"],
    },
]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m graph_builder.cli",
        description="Parse CycloneDX SBOMs into one shared dependency graph.",
    )
    parser.add_argument(
        "--sbom-dir", default="data/sbom",
        help="Directory containing <app_id>.json CycloneDX files (default: data/sbom).",
    )
    parser.add_argument(
        "--load-neo4j", action="store_true",
        help="Also load the merged graph into Neo4j.",
    )
    parser.add_argument("--neo4j-uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    parser.add_argument("--neo4j-user", default=os.environ.get("NEO4J_USER", "neo4j"))
    parser.add_argument("--neo4j-password", default=os.environ.get("NEO4J_PASSWORD", "password"))
    parser.add_argument("--batch-size", type=int, default=500)
    return parser


def run(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_arg_parser().parse_args(argv)

    sbom_dir = Path(args.sbom_dir)
    sbom_files = sorted(sbom_dir.glob("*.json"))
    if not sbom_files:
        print(f"No SBOM files found in {sbom_dir}", file=sys.stderr)
        return 1

    parsed_apps = []
    for path in sbom_files:
        try:
            parsed_apps.append(parse_sbom_file(path))
        except SbomParseError as exc:
            print(f"ERROR parsing {path}: {exc}", file=sys.stderr)
            return 1

    graph = merge_apps(parsed_apps)

    print(f"Applications:     {len(graph.applications)}")
    print(f"Packages:         {len(graph.packages)}")
    print(f"DEPENDS_ON edges: {len(graph.depends_on)}")
    print(f"REQUIRES edges:   {len(graph.requires)}")

    all_ok = True
    for check in SANITY_CHECKS:
        try:
            check_shared_package(
                graph, check["name"], check["version"], check["ecosystem"], check["expected_apps"],
            )
            print(
                f"[sanity] OK: {check['name']}@{check['version']} ({check['ecosystem']}) "
                f"depended on by {check['expected_apps']}"
            )
        except SanityCheckError as exc:
            print(f"[sanity] FAILED: {exc}", file=sys.stderr)
            all_ok = False

    if not all_ok:
        return 1

    if args.load_neo4j:
        from neo4j import GraphDatabase

        from .neo4j_writer import Neo4jWriter

        driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))
        try:
            Neo4jWriter(driver, batch_size=args.batch_size).write_graph(graph)
            print(f"Loaded into Neo4j at {args.neo4j_uri}")
        finally:
            driver.close()

    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
