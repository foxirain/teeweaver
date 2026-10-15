#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from teeweaver.state_machine import coverage_report, proposal_report  # noqa: E402
from teeweaver.elements import load_corpus  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Derive boundary coverage, saturation, and semantic state-machine "
            "experiments from an observed TEEWeaver corpus"
        )
    )
    parser.add_argument(
        "--corpus", type=Path,
        default=PROJECT / "scenarios/mining-corpus-v0.2.json",
    )
    parser.add_argument(
        "--output", type=Path,
        default=PROJECT / "artifacts/state-machine-plan-v0.4.json",
    )
    parser.add_argument("--budget", type=int, default=128)
    parser.add_argument("--saturation-window", type=int, default=5)
    args = parser.parse_args()
    if args.budget < 1:
        parser.error("--budget must be positive")
    if args.saturation_window < 1:
        parser.error("--saturation-window must be positive")

    corpus = args.corpus.resolve()
    runs = load_corpus(PROJECT, corpus)
    coverage = coverage_report(runs, saturation_window=args.saturation_window)
    report = {
        "schema": "teeweaver-discovery-plan-v1",
        "source_corpus": corpus.relative_to(PROJECT).as_posix(),
        "coverage": coverage,
        "experiments": proposal_report(runs, budget=args.budget,
                                       coverage=coverage),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "runs": len(runs),
        "boundary_tuples": report["coverage"]["unique_boundary_tuples"],
        "saturated": report["coverage"]["saturation"]["saturated"],
        "coverage_gaps": report["coverage"]["coverage_gaps"],
        "proposal_counts": report["experiments"]["counts"],
        "execution_modes": report["experiments"]["execution_modes"],
        "output": str(args.output.resolve()),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
