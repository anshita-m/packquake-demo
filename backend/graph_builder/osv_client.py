"""Thin HTTP + caching layer over the OSV API. No parsing logic here (see
vuln_parse.py) -- this module's only job is "get me this JSON, from cache if
possible."

Two OSV calls are involved, deliberately kept separate because OSV's own API
is shaped that way:
  - POST /v1/querybatch: one request for up to `batch_size` packages at
    once, but returns only {id, modified} stubs per vuln (OSV's own
    size-saving tradeoff for batch responses) -- cached per package.
  - GET /v1/vulns/{id}: full vuln detail (aliases, severity, ...) -- cached
    per vuln id, so a vuln affecting many packages (or reachable via
    multiple OSV id aliases) is only ever fetched once.
"""

from __future__ import annotations

import logging

import requests

from .cache import MISSING, DiskCache
from .models import PackageKey
from .osv_ecosystem import to_osv_ecosystem
from .util import chunked

logger = logging.getLogger(__name__)

QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns"

DEFAULT_BATCH_SIZE = 500


def package_cache_key(pkg: PackageKey) -> str:
    return f"pkg__{pkg.ecosystem}__{pkg.name}__{pkg.version}"


class OsvClient:
    def __init__(
        self,
        package_cache: DiskCache,
        vuln_cache: DiskCache,
        session: requests.Session | None = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ):
        self.package_cache = package_cache
        self.vuln_cache = vuln_cache
        self.session = session or requests.Session()
        self.batch_size = batch_size

    def query_vuln_stubs(self, packages: list[PackageKey]) -> dict[PackageKey, list[dict]]:
        """Returns {package: [{"id": ..., "modified": ...}, ...]}."""
        results: dict[PackageKey, list[dict]] = {}
        to_fetch: list[PackageKey] = []

        for pkg in packages:
            cached = self.package_cache.get(package_cache_key(pkg))
            if cached is not MISSING:
                results[pkg] = cached
            else:
                to_fetch.append(pkg)

        for batch in chunked(to_fetch, self.batch_size):
            queryable: list[tuple[PackageKey, str]] = []
            for pkg in batch:
                osv_ecosystem = to_osv_ecosystem(pkg.ecosystem)
                if osv_ecosystem is None:
                    logger.warning(
                        "No OSV ecosystem mapping for purl type %r (package %s@%s); skipping.",
                        pkg.ecosystem, pkg.name, pkg.version,
                    )
                    results[pkg] = []
                    self.package_cache.set(package_cache_key(pkg), [])
                    continue
                queryable.append((pkg, osv_ecosystem))

            if not queryable:
                continue

            body = {
                "queries": [
                    {"package": {"name": pkg.name, "ecosystem": eco}, "version": pkg.version}
                    for pkg, eco in queryable
                ]
            }
            response = self.session.post(QUERYBATCH_URL, json=body, timeout=30)
            response.raise_for_status()
            data = response.json()

            for (pkg, _eco), result in zip(queryable, data.get("results", [])):
                if result.get("next_page_token"):
                    logger.warning(
                        "OSV querybatch result for %s@%s is paginated; only the "
                        "first page was fetched (not implemented).", pkg.name, pkg.version,
                    )
                stubs = result.get("vulns", [])
                results[pkg] = stubs
                self.package_cache.set(package_cache_key(pkg), stubs)

        return results

    def get_vuln_details(self, vuln_ids: set[str]) -> dict[str, dict]:
        """Returns {vuln_id: full OSV vuln JSON}, fetched one per id (each
        individually cached) since OSV's batch endpoint doesn't return full
        detail."""
        details: dict[str, dict] = {}
        for vuln_id in sorted(vuln_ids):
            cached = self.vuln_cache.get(vuln_id)
            if cached is not MISSING:
                details[vuln_id] = cached
                continue
            response = self.session.get(f"{VULN_URL}/{vuln_id}", timeout=30)
            if response.status_code == 404:
                logger.warning("OSV vuln id %r returned 404; skipping.", vuln_id)
                continue
            response.raise_for_status()
            data = response.json()
            details[vuln_id] = data
            self.vuln_cache.set(vuln_id, data)
        return details
