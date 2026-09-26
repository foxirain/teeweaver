#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from teeweaver.secure_trace import read_secure_log  # noqa: E402
from teeweaver.trace import write_jsonl  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Normalize stable OP-TEE secure.log records and explicit TWTRACE "
            "markers into TEEWeaver JSONL"
        )
    )
    parser.add_argument("secure_log", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    events, stats = read_secure_log(args.secure_log)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.output, events)
    print(json.dumps({
        **stats.as_dict(),
        "input": str(args.secure_log.resolve()),
        "output": str(args.output.resolve()),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
