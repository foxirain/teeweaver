#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from teeweaver.discovery import (  # noqa: E402
    build_discovery_bundle,
    render_discovery_markdown,
)
from teeweaver.elements import load_corpus, mine_elements  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Rank dynamically novel histories and emit an AI-consumable "
            "semantic relationship bundle"
        )
    )
    parser.add_argument(
        "--project-root", type=Path, default=PROJECT,
        help="tree against which corpus paths are resolved",
    )
    parser.add_argument(
        "--corpus", type=Path,
        default=Path("scenarios/mining-corpus-v0.2.json"),
    )
    parser.add_argument(
        "--output", type=Path,
        default=PROJECT / "artifacts/discovery-v0.3.json",
    )
    parser.add_argument(
        "--markdown", type=Path,
        default=PROJECT / "artifacts/discovery-v0.3.md",
    )
    parser.add_argument(
        "--budget", type=int, default=32,
        help="maximum histories retained in the greedy discovery queue",
    )
    parser.add_argument(
        "--minimum-element-score", type=int, default=0,
        help="filter legacy v0.2 elements included in the bundle",
    )
    parser.add_argument(
        "--secure-logs", action="store_true",
        help="ingest secure.log beside each corpus trace when present",
    )
    args = parser.parse_args()
    if args.budget < 1:
        parser.error("--budget must be positive")
    if not 0 <= args.minimum_element_score <= 100:
        parser.error("--minimum-element-score must be between 0 and 100")

    project_root = args.project_root.resolve()
    corpus = args.corpus
    if not corpus.is_absolute():
        corpus = project_root / corpus
    corpus = corpus.resolve()
    try:
        spec = corpus.relative_to(project_root).as_posix()
    except ValueError:
        parser.error("--corpus must be inside the project tree")
    runs = load_corpus(project_root, corpus, secure_logs=args.secure_logs)
    elements = [
        item for item in mine_elements(runs)
        if item.score >= args.minimum_element_score
    ]
    bundle = build_discovery_bundle(
        runs, elements, spec=spec, budget=args.budget
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    args.markdown.write_text(
        render_discovery_markdown(bundle), encoding="utf-8"
    )
    print(json.dumps({
        **bundle["summary"],
        "output": str(args.output.resolve()),
        "markdown": str(args.markdown.resolve()),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
