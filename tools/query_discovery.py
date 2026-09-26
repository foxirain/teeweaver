#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from teeweaver.query import select_context  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract a bounded AI context from a TEEWeaver discovery bundle"
    )
    parser.add_argument("bundle", type=Path)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--run")
    selection.add_argument("--feature")
    selection.add_argument("--contrast")
    selection.add_argument("--rank", type=int)
    parser.add_argument("--max-features", type=int, default=96)
    parser.add_argument("--max-edges", type=int, default=128)
    parser.add_argument("--max-elements", type=int, default=32)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    value = json.loads(args.bundle.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        parser.error("bundle must contain a JSON object")
    try:
        context = select_context(
            value,
            run=args.run,
            feature=args.feature,
            contrast=args.contrast,
            rank=args.rank,
            max_features=args.max_features,
            max_edges=args.max_edges,
            max_elements=args.max_elements,
        )
    except ValueError as error:
        parser.error(str(error))
    encoded = json.dumps(context, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(encoded, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
