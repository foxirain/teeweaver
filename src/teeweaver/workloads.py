from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True, slots=True)
class WorkloadTest:
    test_id: str
    suite: str | None
    label: str
    program: str
    arguments: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Workload:
    name: str
    mode: str
    timeout: int
    tests: tuple[WorkloadTest, ...]
    ffa_trace: bool
    campaign_eligible: bool


def load_workloads(path: Path) -> Mapping[str, Workload]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("workload manifest must be an object")
    workloads: dict[str, Workload] = {}
    for name, item in raw.items():
        if not isinstance(item, dict):
            raise ValueError(f"workload {name!r} must be an object")
        mode = str(item.get("mode", "sequential"))
        if mode not in {"sequential", "parallel"}:
            raise ValueError(f"workload {name!r} has unsupported mode {mode!r}")
        timeout = int(item.get("timeout", 180))
        tests_raw = item.get("tests")
        if timeout < 1 or not isinstance(tests_raw, list) or not tests_raw:
            raise ValueError(f"workload {name!r} needs timeout and tests")
        parsed_tests: list[WorkloadTest] = []
        labels: set[str] = set()
        for test in tests_raw:
            test_id = str(test["id"])
            if "suite" in test:
                suite = str(test["suite"]) if test["suite"] else None
            else:
                suite = "regression" if bool(test.get("regression", True)) else None
            label = str(test.get("label", test_id))
            if label in labels:
                raise ValueError(f"workload {name!r} has duplicate label {label!r}")
            labels.add(label)
            program = str(test.get("program", "xtest"))
            if program not in {"xtest", "ffa_probe", "ffa_sequence_probe"}:
                raise ValueError(
                    f"workload {name!r} has unsupported program {program!r}"
                )
            arguments_raw = test.get("arguments", [])
            if not isinstance(arguments_raw, list):
                raise ValueError(
                    f"workload {name!r} test {label!r} arguments must be a list"
                )
            parsed_tests.append(
                WorkloadTest(
                    test_id, suite, label, program,
                    tuple(str(value) for value in arguments_raw),
                )
            )
        workloads[str(name)] = Workload(
            str(name), mode, timeout, tuple(parsed_tests),
            bool(item.get("ffa_trace", False)),
            bool(item.get("campaign_eligible", True)),
        )
    return workloads
