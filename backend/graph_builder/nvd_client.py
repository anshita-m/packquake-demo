"""Thin HTTP + caching layer over the NVD CVE API. Only ever called when
OSV genuinely has no CVSS for a CVE-identified vuln -- expected to be rare.

NVD's unauthenticated rate limit is ~5 requests/30s (~6s/request); an
NVD_API_KEY raises that to ~50/30s (~0.6s/request). We throttle proactively
to that floor between requests, and back off exponentially on a 429 rather
than retrying in a tight loop.
"""

from __future__ import annotations

import logging
import os
import time

import requests

from .cache import MISSING, DiskCache

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

UNAUTHENTICATED_MIN_INTERVAL = 6.2  # seconds; NVD allows ~5 req/30s unauthenticated
AUTHENTICATED_MIN_INTERVAL = 0.65  # seconds; ~50 req/30s with an API key

MAX_RETRIES = 5
INITIAL_BACKOFF = 1.0
MAX_BACKOFF = 60.0


class NvdClient:
    def __init__(
        self,
        cache: DiskCache,
        session: requests.Session | None = None,
        api_key: str | None = None,
        sleep_fn=time.sleep,
        clock_fn=time.monotonic,
    ):
        self.cache = cache
        self.session = session or requests.Session()
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY")
        self.min_interval = AUTHENTICATED_MIN_INTERVAL if self.api_key else UNAUTHENTICATED_MIN_INTERVAL
        self._sleep = sleep_fn
        self._clock = clock_fn
        self._last_request_at: float | None = None

    def get_cve(self, cve_id: str) -> dict | None:
        cached = self.cache.get(cve_id)
        if cached is not MISSING:
            return cached

        data = self._fetch_with_backoff(cve_id)
        if data is not None:
            self.cache.set(cve_id, data)
        return data

    def _fetch_with_backoff(self, cve_id: str) -> dict | None:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        backoff = INITIAL_BACKOFF

        for attempt in range(1, MAX_RETRIES + 1):
            self._throttle()
            response = self.session.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=30)

            if response.status_code == 200:
                return response.json()
            if response.status_code == 404:
                logger.warning("NVD has no record for %s.", cve_id)
                return None
            if response.status_code == 429:
                logger.warning(
                    "NVD rate-limited us on %s (attempt %d/%d); backing off %.1fs.",
                    cve_id, attempt, MAX_RETRIES, backoff,
                )
                self._sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)
                continue

            response.raise_for_status()

        raise RuntimeError(f"NVD lookup for {cve_id} failed after {MAX_RETRIES} retries (rate limited).")

    def _throttle(self) -> None:
        if self._last_request_at is not None:
            elapsed = self._clock() - self._last_request_at
            remaining = self.min_interval - elapsed
            if remaining > 0:
                self._sleep(remaining)
        self._last_request_at = self._clock()
