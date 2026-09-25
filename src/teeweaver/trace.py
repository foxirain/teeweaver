from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .events import Event


def _normalize_ffa_generations(values: list[dict[str, object]]) -> None:
    """Translate process-local FF-A generations into one merged history.

    `arm_ffa_user` handles are kernel-global, while each LD_PRELOAD process has
    only a local observation counter.  The share order is therefore the
    authority for global ABA generations after traces from several actors are
    merged.
    """

    current: dict[str, int] = {}
    local_to_global: dict[tuple[str, str, int], int] = {}
    for value in values:
        op = str(value.get("op", ""))
        if not op.startswith("ffa_") or "object" not in value:
            continue
        obj = str(value["object"])
        process = str(value.get("process", value.get("actor", "unknown")))
        local_generation = int(value.get("generation", 0))
        key = (process, obj, local_generation)
        if op == "ffa_share":
            generation = current.get(obj, 0) + 1
            current[obj] = generation
            local_to_global[key] = generation
            value["local_generation"] = local_generation
            value["generation"] = generation
        elif key in local_to_global:
            value["local_generation"] = local_generation
            value["generation"] = local_to_global[key]


def read_jsonl(path: str | Path) -> list[Event]:
    values: list[dict[str, object]] = []
    with Path(path).open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: event must be an object")
            # errno is only defined after a failing libc call. Some historical
            # traces captured the thread's previous errno after success; do
            # not let that stale value become semantic evidence.
            if int(value.get("ioctl_result", -1)) >= 0 and "ioctl_errno" in value:
                value["ioctl_errno"] = 0
            # Multiple instrumented Normal-World processes append to the same
            # file and therefore have independent local sequence counters.
            # O_APPEND line order is the canonical merged history.
            value["source_seq"] = value.get("seq")
            value["source_order"] = len(values) + 1
            values.append(value)
    if values and all("time_ns" in value for value in values):
        values.sort(
            key=lambda value: (
                int(value["time_ns"]),
                int(value["source_order"]),
            )
        )
    _normalize_ffa_generations(values)
    events: list[Event] = []
    for value in values:
        value["seq"] = len(events) + 1
        events.append(Event.from_dict(value, len(events) + 1))
    return events


def write_jsonl(path: str | Path, events: Iterable[Event]) -> None:
    with Path(path).open("w", encoding="utf-8") as stream:
        for event in events:
            stream.write(json.dumps(event.as_dict(), sort_keys=True))
            stream.write("\n")
