from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Generic, Mapping, Sequence, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Scheduled(Generic[T]):
    actor: str
    index: int
    action: T


def pct_schedule(
    actors: Mapping[str, Sequence[T]], *, seed: int, depth: int = 2
) -> list[Scheduled[T]]:
    """Generate a Probabilistic Concurrency Testing style schedule.

    Actor-local order is preserved. At most ``depth - 1`` priority-change
    points are chosen. The implementation is deterministic for a given seed.
    """

    if depth < 1:
        raise ValueError("depth must be at least one")
    rng = random.Random(seed)
    names = sorted(actors)
    priorities = names[:]
    rng.shuffle(priorities)
    rank = {name: len(names) - index for index, name in enumerate(priorities)}
    total = sum(len(actions) for actions in actors.values())
    change_points = set(rng.sample(range(1, total + 1), min(depth - 1, total)))
    positions = {name: 0 for name in names}
    output: list[Scheduled[T]] = []

    for step in range(1, total + 1):
        enabled = [name for name in names if positions[name] < len(actors[name])]
        selected = max(enabled, key=lambda name: (rank[name], name))
        if step in change_points:
            rank[selected] = min(rank.values(), default=0) - 1
            selected = max(enabled, key=lambda name: (rank[name], name))
        index = positions[selected]
        output.append(Scheduled(selected, index, actors[selected][index]))
        positions[selected] += 1
    return output

