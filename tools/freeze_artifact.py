#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from teeweaver.freeze import build_manifest, read_manifest, verify_manifest  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Freeze or verify an advisory-blind TEEWeaver artifact"
    )
    parser.add_argument("--label", default="v0.4.0-alpha-development-freeze")
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT / "artifacts/freeze-v0.4.0-alpha.json",
    )
    parser.add_argument(
        "--verify",
        type=Path,
        help="verify the current tree against an existing freeze manifest",
    )
    args = parser.parse_args()

    if args.verify:
        decision = verify_manifest(PROJECT, read_manifest(args.verify))
        print(json.dumps({
            "valid": decision.valid,
            "missing": decision.missing,
            "changed": decision.changed,
            "unexpected": decision.unexpected,
        }, indent=2))
        return 0 if decision.valid else 1

    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = build_manifest(PROJECT, label=args.label)
    output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(output)
    print(manifest["aggregate_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
