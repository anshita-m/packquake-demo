"""Minimal Package URL (purl) parsing.

We only need the ecosystem (purl "type"), name, and version out of a purl —
not full spec compliance (qualifiers, subpaths are discarded).
Spec: https://github.com/package-url/purl-spec
"""

from __future__ import annotations

import re
from urllib.parse import unquote

_PURL_RE = re.compile(r"^pkg:(?P<type>[^/]+)/(?P<rest>.+)$")


def parse_purl(purl: str) -> tuple[str, str, str]:
    """Parse a purl string into (ecosystem, name, version).

    Handles namespaced packages (pkg:type/namespace/name@version, e.g. Maven
    or scoped npm packages), percent-encoded segments, and strips any
    qualifiers (?...) or subpath (#...) suffix.

    Raises ValueError if `purl` is not a parseable purl.
    """
    if not purl or not purl.startswith("pkg:"):
        raise ValueError(f"not a purl: {purl!r}")

    match = _PURL_RE.match(purl)
    if not match:
        raise ValueError(f"malformed purl: {purl!r}")

    ecosystem = unquote(match.group("type")).lower()
    rest = match.group("rest")

    # Strip subpath and qualifiers, in either order.
    rest = rest.split("#", 1)[0]
    rest = rest.split("?", 1)[0]

    if "@" in rest:
        path_part, version = rest.rsplit("@", 1)
    else:
        path_part, version = rest, ""

    segments = [unquote(seg) for seg in path_part.split("/") if seg]
    if not segments:
        raise ValueError(f"purl has no name: {purl!r}")

    if len(segments) > 1:
        name = "/".join(segments)
    else:
        name = segments[0]

    return ecosystem, name, unquote(version)
