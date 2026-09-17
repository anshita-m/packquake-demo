"""CLI entry point for Phase 7:
python -m graph_builder.mitigation_cli [--top N] [--package name@version@ecosystem]

Reads each package's already-stored Phase 6 raw factors straight off the
Package node (no recomputation -- reuses Phase 6's numbers exactly as
written) plus Phase 3's already-cached OSV fixed-version data (no network
calls), ranks vulnerable packages by patch priority, and prints the list
plus each one's one-sentence explanation.
"""

from __future__ import annotations

import argparse
import os
import sys

from .mitigation_service import compute_ranked_mitigations
from .risk_score import DEFAULT_WEIGHTS


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m graph_builder.mitigation_cli")
    parser.add_argument("--neo4j-uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    parser.add_argument("--neo4j-user", default=os.environ.get("NEO4J_USER", "neo4j"))
    parser.add_argument("--neo4j-password", default=os.environ.get("NEO4J_PASSWORD", "password"))
    parser.add_argument("--osv-cache", default="data/osv_cache")
    parser.add_argument("--top", type=int, default=10, help="How many ranked entries to print (default 10).")
    parser.add_argument("--package", help="name@version@ecosystem -- print this one package's ranking entry too, if present.")
    return parser


def _print_entry(rank: int, entry: dict) -> None:
    pkg = entry["package"]
    effort_str = entry["effort"] if entry["effort"] is not None else "unknown"
    print(f"{rank}. {pkg['name']}@{pkg['version']} ({pkg['ecosystem']}) -- priority={entry['priority']:.4f}")
    print(f"   risk_score {entry['risk_score_before']:.4f} -> {entry['risk_score_after']:.4f} "
          f"(reduction {entry['risk_reduction']:.4f}), effort={effort_str}, fixed_version={entry['fixed_version']}")
    print(f"   {entry['explanation']}")


def run(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))
    try:
        ranked, total_read, skipped_no_phase6 = compute_ranked_mitigations(driver, args.osv_cache, DEFAULT_WEIGHTS)
    finally:
        driver.close()

    if skipped_no_phase6:
        print(f"NOTE: {skipped_no_phase6} vulnerable package(s) skipped -- Phase 6 hasn't computed "
              f"raw factors for them yet (run risk_cli first).", file=sys.stderr)

    print(f"{len(ranked)} vulnerable packages ranked (of {total_read} total), sorted by priority descending")
    print()

    for i, entry in enumerate(ranked[: args.top], start=1):
        _print_entry(i, entry)

    if args.package:
        name, version, ecosystem = args.package.split("@")
        match = next(
            (e for e in ranked if e["package"] == {"name": name, "version": version, "ecosystem": ecosystem}), None,
        )
        print()
        print(f"=== {args.package} ===")
        if match is None:
            print("  not in the ranking (no vulnerabilities, Phase 6 hasn't run on it, or not found)")
        else:
            rank = ranked.index(match) + 1
            _print_entry(rank, match)

    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
