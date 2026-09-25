#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from teeweaver.elements import (  # noqa: E402
    build_report,
    load_corpus,
    mine_elements,
    render_markdown,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Mine AI-consumable dynamic elements from TEEWeaver histories"
    )
    parser.add_argument(
        "--corpus", type=Path,
        default=PROJECT / "scenarios/mining-corpus-v0.2.json",
    )
    parser.add_argument(
        "--output", type=Path,
        default=PROJECT / "artifacts/elements-v0.2.json",
    )
    parser.add_argument(
        "--markdown", type=Path,
        default=PROJECT / "artifacts/elements-v0.2.md",
    )
    parser.add_argument(
        "--minimum-score", type=int, default=0,
        help="omit elements below this score (0-100)",
    )
    args = parser.parse_args()
    if not 0 <= args.minimum_score <= 100:
        parser.error("--minimum-score must be between 0 and 100")

    corpus = args.corpus.resolve()
    runs = load_corpus(PROJECT, corpus)
    elements = [item for item in mine_elements(runs)
                if item.score >= args.minimum_score]
    report = build_report(
        runs, elements, spec=corpus.relative_to(PROJECT).as_posix()
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    args.markdown.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({
        "runs": len(runs),
        "events": report["corpus_summary"]["events"],
        "elements": len(elements),
        "counts": report["element_counts"],
        "output": str(args.output.resolve()),
        "markdown": str(args.markdown.resolve()),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
