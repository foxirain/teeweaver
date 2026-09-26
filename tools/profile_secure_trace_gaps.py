#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from teeweaver.secure_trace import profile_secure_gaps  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Rank normalized OP-TEE secure.log callsite shapes not modeled by "
            "the current TEEWeaver parser"
        )
    )
    parser.add_argument("secure_logs", type=Path, nargs="+")
    parser.add_argument("--limit", type=int, default=256)
    parser.add_argument("--minimum-count", type=int, default=1)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = profile_secure_gaps(
            args.secure_logs, limit=args.limit,
            minimum_count=args.minimum_count,
        )
    except ValueError as error:
        parser.error(str(error))
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(encoded, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
