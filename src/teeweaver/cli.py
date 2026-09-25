from __future__ import annotations

import argparse
import json
from pathlib import Path

from .campaign import plan_faults
from .minimize import ddmin
from .oracles import check
from .trace import read_jsonl, write_jsonl


def _print_result(events, violations, stimuli, coverage: int) -> None:
    print(
        json.dumps(
            {
                "events": len(events),
                "semantic_states": coverage,
                "stimuli": [
                    {
                        "code": stimulus.code,
                        "seq": stimulus.seq,
                        "message": stimulus.message,
                        "evidence": stimulus.evidence,
                    }
                    for stimulus in stimuli
                ],
                "violations": [
                    {
                        "code": violation.code,
                        "seq": violation.seq,
                        "message": violation.message,
                        "evidence": violation.evidence,
                    }
                    for violation in violations
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )


def command_check(path: str) -> int:
    events = read_jsonl(path)
    violations, stimuli, coverage = check(events)
    _print_result(events, violations, stimuli, coverage)
    return 2 if violations else 0


def command_minimize(source: str, destination: str, code: str | None) -> int:
    events = read_jsonl(source)
    original, _, _ = check(events)
    if not original:
        raise SystemExit("trace has no invariant violation")
    target_code = code or original[0].code

    def interesting(candidate) -> bool:
        violations, _, _ = check(candidate)
        return any(violation.code == target_code for violation in violations)

    minimized = ddmin(events, interesting)
    write_jsonl(destination, minimized)
    violations, stimuli, coverage = check(minimized)
    _print_result(minimized, violations, stimuli, coverage)
    print(f"wrote {Path(destination).resolve()}")
    return 0


def command_plan(source: str, seed: int, budget: int) -> int:
    events = read_jsonl(source)
    surfaces, plans = plan_faults(events, seed=seed, budget=budget)
    print(
        json.dumps(
            {
                "seed": seed,
                "budget": budget,
                "surface": [
                    {
                        "func": item.func,
                        "occurrences": item.occurrences,
                        "max_params": item.max_params,
                        "memref_positions": list(item.memref_positions),
                    }
                    for item in surfaces
                ],
                "faults": [item.as_dict() for item in plans],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="teeweaver")
    subparsers = parser.add_subparsers(dest="command", required=True)
    check_parser = subparsers.add_parser("check", help="check a JSONL history")
    check_parser.add_argument("trace")
    min_parser = subparsers.add_parser("minimize", help="delta-minimize a violation")
    min_parser.add_argument("trace")
    min_parser.add_argument("output")
    min_parser.add_argument("--code", help="violation code to preserve")
    plan_parser = subparsers.add_parser(
        "plan", help="derive an advisory-blind fault plan from a baseline trace"
    )
    plan_parser.add_argument("trace")
    plan_parser.add_argument("--seed", type=int, default=1)
    plan_parser.add_argument("--budget", type=int, default=32)
    args = parser.parse_args()
    if args.command == "check":
        raise SystemExit(command_check(args.trace))
    if args.command == "minimize":
        raise SystemExit(command_minimize(args.trace, args.output, args.code))
    raise SystemExit(command_plan(args.trace, args.seed, args.budget))


if __name__ == "__main__":
    main()
