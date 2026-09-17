"""Package identifiers for the API: "ecosystem:name@version", e.g.
"npm:lodash@4.17.21" or "npm:@babel/helper-string-parser@7.29.7".

Scoped npm names contain their own "/" and "@" (the scope's own prefix),
so version is split off with the LAST "@", not the first -- and the id as
a whole can contain "/", which is why routes using it take it as a
:path-typed path parameter (see api.py) rather than a plain path segment.
"""

from __future__ import annotations

from .models import PackageKey


class InvalidPackageId(ValueError):
    pass


def to_package_id(package: PackageKey) -> str:
    return f"{package.ecosystem}:{package.name}@{package.version}"


def from_package_id(package_id: str) -> PackageKey:
    ecosystem, sep, rest = package_id.partition(":")
    if not sep:
        raise InvalidPackageId(f"expected 'ecosystem:name@version', got {package_id!r}")
    name, sep2, version = rest.rpartition("@")
    if not sep2:
        raise InvalidPackageId(f"expected 'ecosystem:name@version', got {package_id!r}")
    return PackageKey(name=name, version=version, ecosystem=ecosystem)
