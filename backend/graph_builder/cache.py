"""A dumb disk cache: one JSON file per key, plus hit/miss counters.

Deliberately not content-aware -- callers decide what a "key" is (a package
triple, a vuln id, a CVE id, ...) and what JSON-serializable value to store.
Used by osv_client / nvd_client / epss_client so every run can prove "zero
additional network calls" by inspecting `.stats` after a second run.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Sentinel distinguishing "not cached" from "cached value is null/None/[]/{}".
MISSING = object()

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9_.@=-]")


def _sanitize(key: str) -> str:
    return _UNSAFE_CHARS.sub("_", key)


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0

    def __str__(self) -> str:
        return f"{self.hits} hits, {self.misses} misses"


class DiskCache:
    def __init__(self, root: Path | str, name: str = "cache"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.name = name
        self.stats = CacheStats()

    def get(self, key: str) -> Any:
        """Returns the cached value, or the MISSING sentinel if not cached."""
        path = self._path(key)
        if not path.exists():
            self.stats.misses += 1
            logger.debug("[%s] cache MISS: %s", self.name, key)
            return MISSING
        self.stats.hits += 1
        logger.debug("[%s] cache HIT: %s", self.name, key)
        with open(path, encoding="utf-8") as f:
            return json.load(f)["value"]

    def set(self, key: str, value: Any) -> None:
        path = self._path(key)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"key": key, "value": value}, f)

    def _path(self, key: str) -> Path:
        return self.root / f"{_sanitize(key)}.json"
