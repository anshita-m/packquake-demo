"""CLI entry point for Phase 6:
python -m graph_builder.risk_cli [--dry-run] [--package name@version@ecosystem]

Reads Package/Vulnerability data + the live Application count out of Neo4j
(Phase 4/3 must have run already), computes runtime_exposure + the 5 raw
factors + weighted terms + risk_score per package, writes them back, and
prints the full breakdown for the real, naturally-shared package (or one
specific package on request via --package).
"""

from __future__ import annotations

import argparse
import os
import sys

from .models import PackageKey
from .neo4j_risk_reader import read_packages_for_risk_scoring, read_total_apps
from .neo4j_risk_writer import Neo4jRiskWriter
from .risk_score import DEFAULT_WEIGHTS, compute_raw_factors, score_package
from .runtime_exposure import runtime_exposure_for_package

# See cli.py's SANITY_CHECKS comment: accepts@1.3.8 is the one real,
# naturally-shared package right now. No Python-side equivalent currently
# exists (microblog/flack's real pins don't overlap).
SPOTLIGHT_PACKAGES = [
    PackageKey("accepts", "1.3.8", "npm"),
]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m graph_builder.risk_cli")
    parser.add_argument("--neo4j-uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    parser.add_argument("--neo4j-user", default=os.environ.get("NEO4J_USER", "neo4j"))
    parser.add_argument("--neo4j-password", default=os.environ.get("NEO4J_PASSWORD", "password"))
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--dry-run", action="store_true", help="Compute and print but don't write back.")
    parser.add_argument("--package", help="name@version@ecosystem -- print this package's breakdown too.")
    return parser


def _print_breakdown(pkg: PackageKey, entry: dict) -> None:
    print(f"  {pkg.name}@{pkg.version} ({pkg.ecosystem}):")
    print(f"    risk_score = {entry['risk_score']:.4f}")
    for name, raw in entry["raw_factors"].items():
        weighted = entry["weighted_terms"][name]
        print(f"      {name:22s} raw={raw:.4f}  weighted={weighted:.4f}")


def run(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))
    try:
        total_apps = read_total_apps(driver)
        package_inputs = read_packages_for_risk_scoring(driver)
        print(f"Read {len(package_inputs)} packages, {total_apps} applications")

        if not package_inputs:
            print("No Package nodes found -- run Phase 2's --load-neo4j first.", file=sys.stderr)
            return 1

        scored: dict[PackageKey, dict] = {}
        for pkg_input in package_inputs:
            exposure = runtime_exposure_for_package(pkg_input.blast_radius_apps)
            raw_factors = compute_raw_factors(
                vulnerabilities=pkg_input.vulnerabilities,
                betweenness_centrality=pkg_input.betweenness_centrality,
                blast_radius_apps=pkg_input.blast_radius_apps,
                total_apps=total_apps,
                runtime_exposure=exposure,
            )
            result = score_package(raw_factors, DEFAULT_WEIGHTS)
            scored[pkg_input.package] = {"raw_factors": raw_factors, **result}

        print(f"Computed risk scores for {len(scored)} packages")

        if not args.dry_run:
            Neo4jRiskWriter(driver, batch_size=args.batch_size).write_risk_scores(scored)
            print(f"Wrote 5 raw factors + 5 weighted terms + risk_score onto {len(scored)} Package nodes")

        print()
        print("=== naturally-shared packages ===")
        for pkg in SPOTLIGHT_PACKAGES:
            entry = scored.get(pkg)
            if entry is None:
                print(f"  {pkg.name}@{pkg.version} ({pkg.ecosystem}): NOT FOUND IN GRAPH")
                continue
            _print_breakdown(pkg, entry)

        if args.package:
            name, version, ecosystem = args.package.split("@")
            pkg = PackageKey(name, version, ecosystem)
            entry = scored.get(pkg)
            print()
            print(f"=== {args.package} ===")
            if entry is None:
                print(f"  NOT FOUND IN GRAPH")
            else:
                _print_breakdown(pkg, entry)

        return 0
    finally:
        driver.close()


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
