from __future__ import annotations

from typing import Iterable, Iterator, TypeVar

T = TypeVar("T")


def chunked(items: list[T], size: int) -> Iterator[list[T]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]
