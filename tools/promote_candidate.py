#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from teeweaver.promotion import decide_promotion  # noqa: E402


def read_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object in {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply TEEWeaver's reportability gate to one candidate"
    )
    parser.add_argument("summary", type=Path)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    decision = decide_promotion(
        read_object(args.summary), read_object(args.evidence)
    ).as_dict()
    rendered = json.dumps(decision, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if decision["promotable"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
