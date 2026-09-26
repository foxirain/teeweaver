#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from teeweaver.discovery import profile_runs  # noqa: E402
from teeweaver.discovery_index import NoveltyIndex  # noqa: E402
from teeweaver.elements import iter_corpus  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Incrementally retain corpus histories that add semantic discovery "
            "coverage or a controlled contrast"
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
        "--input-index", type=Path,
        help="optional prior teeweaver-novelty-index-v1 JSON",
    )
    parser.add_argument(
        "--output-index", type=Path,
        default=PROJECT / "artifacts/discovery-index-v0.3.json",
    )
    parser.add_argument(
        "--decisions", type=Path,
        default=PROJECT / "artifacts/discovery-decisions-v0.3.json",
    )
    parser.add_argument(
        "--secure-logs", action="store_true",
        help="ingest secure.log beside each corpus trace when present",
    )
    args = parser.parse_args()

    project_root = args.project_root.resolve()
    corpus = args.corpus
    if not corpus.is_absolute():
        corpus = project_root / corpus
    if args.input_index is not None:
        loaded = json.loads(args.input_index.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            parser.error("--input-index must contain a JSON object")
        index = NoveltyIndex.from_dict(loaded)
    else:
        index = NoveltyIndex()
    decisions = []
    for run in iter_corpus(
        project_root, corpus.resolve(), secure_logs=args.secure_logs,
    ):
        profile = profile_runs([run])[0][0]
        decisions.append(index.ingest(profile))

    args.output_index.parent.mkdir(parents=True, exist_ok=True)
    args.decisions.parent.mkdir(parents=True, exist_ok=True)
    args.output_index.write_text(
        json.dumps(index.as_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.decisions.write_text(
        json.dumps({
            "schema": "teeweaver-index-decisions-v1",
            "meaning": (
                "Corpus-retention decisions for discovery throughput; not "
                "vulnerability findings or severity judgments."
            ),
            "decisions": [decision.as_dict() for decision in decisions],
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "observed_runs": index.observed_runs,
        "retained_runs": len(index.retained_profiles),
        "dispositions": {
            disposition: sum(
                decision.disposition == disposition for decision in decisions
            )
            for disposition in sorted({decision.disposition for decision in decisions})
        },
        "index": str(args.output_index.resolve()),
        "decisions": str(args.decisions.resolve()),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
