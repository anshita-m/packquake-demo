"""CLI to manually flip blocks_propagation on a REQUIRES edge, for the
Phase 5 demo (e.g. simulating "this package pins an incompatible exact
version, so a compromise upstream can't actually reach it").

    python -m graph_builder.propagation_cli set some-package@1.0.0@npm lodash@4.17.21@npm true
    python -m graph_builder.propagation_cli get some-package@1.0.0@npm lodash@4.17.21@npm
"""

from __future__ import annotations

import argparse
import os
import sys

from .models import PackageKey
from .neo4j_propagation import get_blocks_propagation, set_blocks_propagation


def _parse_package(spec: str) -> PackageKey:
    parts = spec.split("@")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            f"expected name@version@ecosystem, got {spec!r} (e.g. lodash@4.17.21@npm)"
        )
    name, version, ecosystem = parts
    return PackageKey(name=name, version=version, ecosystem=ecosystem)


def _parse_bool(value: str) -> bool:
    if value.lower() in ("true", "1", "yes"):
        return True
    if value.lower() in ("false", "0", "no"):
        return False
    raise argparse.ArgumentTypeError(f"expected true/false, got {value!r}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m graph_builder.propagation_cli")
    parser.add_argument("--neo4j-uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    parser.add_argument("--neo4j-user", default=os.environ.get("NEO4J_USER", "neo4j"))
    parser.add_argument("--neo4j-password", default=os.environ.get("NEO4J_PASSWORD", "password"))

    subparsers = parser.add_subparsers(dest="action", required=True)

    set_parser = subparsers.add_parser("set", help="Set blocks_propagation on a REQUIRES edge.")
    set_parser.add_argument("dependent", type=_parse_package, help="name@version@ecosystem, e.g. some-package@1.0.0@npm")
    set_parser.add_argument("dependency", type=_parse_package, help="name@version@ecosystem, e.g. lodash@4.17.21@npm")
    set_parser.add_argument("blocks", type=_parse_bool, help="true or false")

    get_parser = subparsers.add_parser("get", help="Print the current blocks_propagation value on a REQUIRES edge.")
    get_parser.add_argument("dependent", type=_parse_package)
    get_parser.add_argument("dependency", type=_parse_package)

    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))
    try:
        if args.action == "set":
            set_blocks_propagation(driver, args.dependent, args.dependency, args.blocks)
            print(f"blocks_propagation={args.blocks} set on {args.dependent.name}@{args.dependent.version} -> {args.dependency.name}@{args.dependency.version}")
        elif args.action == "get":
            value = get_blocks_propagation(driver, args.dependent, args.dependency)
            print(value)
        return 0
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        driver.close()


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
