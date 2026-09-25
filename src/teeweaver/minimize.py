from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TypeVar

T = TypeVar("T")


def ddmin(items: Sequence[T], interesting: Callable[[list[T]], bool]) -> list[T]:
    """Classic delta debugging over an ordered history."""

    current = list(items)
    if not interesting(current):
        raise ValueError("input is not interesting")
    granularity = 2
    while len(current) >= 2:
        chunk = (len(current) + granularity - 1) // granularity
        reduced = False
        for start in range(0, len(current), chunk):
            candidate = current[:start] + current[start + chunk :]
            if candidate and interesting(candidate):
                current = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if not reduced:
            if granularity >= len(current):
                break
            granularity = min(len(current), granularity * 2)
    return current

