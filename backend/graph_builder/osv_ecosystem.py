"""Map our Package.ecosystem (a purl "type" string, lowercase) to OSV's own
ecosystem strings.

These are NOT the same casing/spelling -- e.g. our purl-derived ecosystem is
"pypi" but OSV expects "PyPI". Taken from OSV's documented ecosystem list
(https://ossf.github.io/osv-schema/#affectedpackage-field) cross-referenced
against purl-spec's known package types
(https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst) --
not guessed by capitalizing the purl type.
"""

from __future__ import annotations

PURL_TYPE_TO_OSV_ECOSYSTEM: dict[str, str] = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "cargo": "crates.io",
    "golang": "Go",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
    "pub": "Pub",
    "hex": "Hex",
    "conan": "ConanCenter",
    "swift": "SwiftURL",
}


def to_osv_ecosystem(purl_ecosystem: str) -> str | None:
    """Returns the OSV ecosystem string, or None if we have no mapping."""
    return PURL_TYPE_TO_OSV_ECOSYSTEM.get(purl_ecosystem.lower())
