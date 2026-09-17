"""CLI entry point for Phase 3:
python -m graph_builder.enrich_cli --sbom-dir data/sbom [--load-neo4j] [--app APP_ID]

Rebuilds the same in-memory Graph Phase 2's CLI builds (by re-parsing the
SBOMs -- cheap and deterministic, no need to read it back from Neo4j),
enriches every Package with OSV/NVD/EPSS data, prints cache-hit/miss stats,
and optionally writes Vulnerability nodes + AFFECTED_BY edges into Neo4j
(assumes Application/Package nodes are already there from a Phase 2
`--load-neo4j` run).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .cache import DiskCache
from .cyclonedx_parser import SbomParseError, parse_sbom_file
from .enrichment import enrich_graph
from .epss_client import EpssClient
from .graph_merge import merge_apps
from .nvd_client import NvdClient
from .osv_client import OsvClient
from .queries import vulnerabilities_for_app

logger = logging.getLogger(__name__)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m graph_builder.enrich_cli",
        description="Enrich every Package node with OSV/NVD/EPSS vulnerability data.",
    )
    parser.add_argument("--sbom-dir", default="data/sbom")
    parser.add_argument("--osv-cache", default="data/osv_cache")
    parser.add_argument("--nvd-cache", default="data/nvd_cache")
    parser.add_argument("--epss-cache", default="data/epss_cache")
    parser.add_argument("--load-neo4j", action="store_true")
    parser.add_argument("--neo4j-uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    parser.add_argument("--neo4j-user", default=os.environ.get("NEO4J_USER", "neo4j"))
    parser.add_argument("--neo4j-password", default=os.environ.get("NEO4J_PASSWORD", "password"))
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--app", help="After enriching, print vulnerabilities found for just this app_id.")
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
    print(f"Enriching {len(graph.packages)} packages across {len(graph.applications)} apps...")

    osv_package_cache = DiskCache(Path(args.osv_cache) / "packages", name="osv-package")
    osv_vuln_cache = DiskCache(Path(args.osv_cache) / "vulns", name="osv-vuln")
    nvd_cache = DiskCache(args.nvd_cache, name="nvd")
    epss_cache = DiskCache(args.epss_cache, name="epss")

    osv_client = OsvClient(osv_package_cache, osv_vuln_cache, batch_size=args.batch_size)
    nvd_client = NvdClient(nvd_cache)
    epss_client = EpssClient(epss_cache)

    vuln_graph = enrich_graph(graph, osv_client, nvd_client, epss_client)

    with_cvss = sum(1 for v in vuln_graph.vulnerabilities.values() if v.cvss_score is not None)
    with_epss = sum(1 for v in vuln_graph.vulnerabilities.values() if v.epss_score is not None)

    print(f"Vulnerabilities found:   {len(vuln_graph.vulnerabilities)}")
    print(f"  with CVSS score:       {with_cvss}")
    print(f"  with EPSS score:       {with_epss}")
    print(f"AFFECTED_BY edges:       {len(vuln_graph.affected_by)}")
    print()
    print(f"OSV package-batch cache: {osv_package_cache.stats}")
    print(f"OSV vuln-detail cache:   {osv_vuln_cache.stats}")
    print(f"NVD cache:               {nvd_cache.stats}")
    print(f"EPSS cache:              {epss_cache.stats}")

    if args.app:
        print()
        print(f"=== vulnerabilities for app_id={args.app!r} ===")
        per_package = vulnerabilities_for_app(graph, vuln_graph, args.app)
        if not per_package:
            print(f"(none found for {args.app!r} -- double check the app_id)")
        for pkg, vulns in sorted(per_package.items(), key=lambda kv: (kv[0].name, kv[0].version)):
            for v in sorted(vulns, key=lambda v: -(v.cvss_score or 0)):
                print(
                    f"  {pkg.name}@{pkg.version} ({pkg.ecosystem}) -- {v.vuln_id} "
                    f"[{v.id_type}] cvss={v.cvss_score} ({v.cvss_severity}, src={v.cvss_source}) "
                    f"epss={v.epss_score}"
                )

    if args.load_neo4j:
        from neo4j import GraphDatabase

        from .neo4j_vuln_writer import Neo4jVulnWriter

        driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))
        try:
            Neo4jVulnWriter(driver, batch_size=args.batch_size).write_vuln_graph(vuln_graph)
            print(f"Loaded vulnerability graph into Neo4j at {args.neo4j_uri}")
        finally:
            driver.close()

    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
