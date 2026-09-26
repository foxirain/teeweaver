from __future__ import annotations

import argparse
import json
from pathlib import Path

from .campaign import plan_faults
from .discovery import build_discovery_bundle, render_discovery_markdown
from .elements import load_corpus, mine_elements
from .minimize import ddmin
from .oracles import check
from .query import select_context
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


def command_discover(
    project: str, corpus: str, output: str | None,
    markdown: str | None, budget: int, secure_logs: bool,
) -> int:
    root = Path(project).resolve()
    corpus_path = Path(corpus)
    if not corpus_path.is_absolute():
        corpus_path = root / corpus_path
    corpus_path = corpus_path.resolve()
    try:
        spec = corpus_path.relative_to(root).as_posix()
    except ValueError as error:
        raise SystemExit("corpus must be inside --project") from error
    runs = load_corpus(root, corpus_path, secure_logs=secure_logs)
    elements = mine_elements(runs)
    bundle = build_discovery_bundle(
        runs, elements, spec=spec, budget=budget
    )
    encoded = json.dumps(bundle, indent=2, sort_keys=True) + "\n"
    if output:
        destination = Path(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    if markdown:
        destination = Path(markdown)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            render_discovery_markdown(bundle), encoding="utf-8"
        )
    return 0


def command_query(
    bundle: str, *, run: str | None, feature: str | None,
    contrast: str | None, rank: int | None, max_features: int,
    max_edges: int, max_elements: int, output: str | None,
) -> int:
    value = json.loads(Path(bundle).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit("bundle must contain a JSON object")
    context = select_context(
        value, run=run, feature=feature, contrast=contrast, rank=rank,
        max_features=max_features, max_edges=max_edges,
        max_elements=max_elements,
    )
    encoded = json.dumps(context, indent=2, sort_keys=True) + "\n"
    if output:
        destination = Path(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
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
    discover_parser = subparsers.add_parser(
        "discover",
        help="rank semantic novelty and emit an AI-consumable discovery bundle",
    )
    discover_parser.add_argument("corpus")
    discover_parser.add_argument("--project", default=".")
    discover_parser.add_argument("--output")
    discover_parser.add_argument("--markdown")
    discover_parser.add_argument("--budget", type=int, default=32)
    discover_parser.add_argument(
        "--secure-logs", action="store_true",
        help="ingest secure.log beside each corpus trace when present",
    )
    query_parser = subparsers.add_parser(
        "query", help="extract a bounded AI context from a discovery bundle"
    )
    query_parser.add_argument("bundle")
    query_selection = query_parser.add_mutually_exclusive_group()
    query_selection.add_argument("--run")
    query_selection.add_argument("--feature")
    query_selection.add_argument("--contrast")
    query_selection.add_argument("--rank", type=int)
    query_parser.add_argument("--max-features", type=int, default=96)
    query_parser.add_argument("--max-edges", type=int, default=128)
    query_parser.add_argument("--max-elements", type=int, default=32)
    query_parser.add_argument("--output")
    args = parser.parse_args()
    if args.command == "check":
        raise SystemExit(command_check(args.trace))
    if args.command == "minimize":
        raise SystemExit(command_minimize(args.trace, args.output, args.code))
    if args.command == "plan":
        raise SystemExit(command_plan(args.trace, args.seed, args.budget))
    if args.command == "discover":
        if args.budget < 1:
            parser.error("--budget must be positive")
        raise SystemExit(command_discover(
            args.project, args.corpus, args.output, args.markdown, args.budget,
            args.secure_logs,
        ))
    try:
        raise SystemExit(command_query(
            args.bundle, run=args.run, feature=args.feature,
            contrast=args.contrast, rank=args.rank,
            max_features=args.max_features, max_edges=args.max_edges,
            max_elements=args.max_elements, output=args.output,
        ))
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
