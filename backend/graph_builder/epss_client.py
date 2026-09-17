"""Thin HTTP + caching layer over FIRST.org's EPSS API. Batches CVEs into
one comma-separated request per chunk (never one request per CVE), and
caches per-CVE so a re-run only fetches newly-discovered CVEs.

A CVE genuinely absent from EPSS's dataset is cached as `None` (not just
skipped) so we don't re-request it on every run either.
"""

from __future__ import annotations

import requests

from .cache import MISSING, DiskCache
from .util import chunked

EPSS_URL = "https://api.first.org/data/v1/epss"

# EPSS's API page-limits results (default/observed cap: 100 rows per
# response); keep each request's CVE count at or under that so one request
# always yields one complete page, with no pagination to handle.
DEFAULT_BATCH_SIZE = 100


class EpssClient:
    def __init__(self, cache: DiskCache, session: requests.Session | None = None, batch_size: int = DEFAULT_BATCH_SIZE):
        self.cache = cache
        self.session = session or requests.Session()
        self.batch_size = batch_size

    def get_scores(self, cve_ids: list[str]) -> dict[str, dict | None]:
        """Returns {cve_id: {"cve":..,"epss":..,"percentile":..,"date":..} | None}."""
        results: dict[str, dict | None] = {}
        to_fetch: list[str] = []

        for cve_id in cve_ids:
            cached = self.cache.get(cve_id)
            if cached is not MISSING:
                results[cve_id] = cached
            else:
                to_fetch.append(cve_id)

        for batch in chunked(sorted(set(to_fetch)), self.batch_size):
            response = self.session.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=30)
            response.raise_for_status()
            data = response.json()
            rows_by_cve = {row["cve"]: row for row in data.get("data", [])}

            for cve_id in batch:
                row = rows_by_cve.get(cve_id)
                results[cve_id] = row
                self.cache.set(cve_id, row)

        return results
