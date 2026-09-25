#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

PROJECT = Path(__file__).resolve().parents[1]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_subset(observed: Any, expected: Any, location: str = "$") -> None:
    if isinstance(expected, dict):
        if not isinstance(observed, dict):
            raise ValueError(f"{location}: expected object")
        for key, value in expected.items():
            if key not in observed:
                raise ValueError(f"{location}: missing key {key!r}")
            require_subset(observed[key], value, f"{location}.{key}")
        return
    if observed != expected:
        raise ValueError(f"{location}: expected {expected!r}, observed {observed!r}")


def codes(value: Mapping[str, Any], field: str) -> list[str]:
    items = value.get(field, [])
    if not isinstance(items, list):
        raise ValueError(f"{field} is not a list")
    return [str(item.get("code")) for item in items if isinstance(item, dict)]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate adopted TEEWeaver results and hash every evidence file"
    )
    parser.add_argument(
        "--spec",
        type=Path,
        default=PROJECT / "scenarios/evidence-v0.2.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT / "artifacts/evidence-v0.2.0-alpha.json",
    )
    parser.add_argument(
        "--verify",
        type=Path,
        help="verify the adopted result files against an existing manifest",
    )
    args = parser.parse_args()

    records = json.loads(args.spec.read_text(encoding="utf-8"))
    if not isinstance(records, list) or not records:
        raise SystemExit("evidence specification must be a non-empty list")

    adopted: list[dict[str, Any]] = []
    aggregate = hashlib.sha256()
    for record in records:
        if not isinstance(record, dict):
            raise SystemExit("each evidence record must be an object")
        relative = Path(str(record["path"]))
        directory = (PROJECT / relative).resolve()
        if PROJECT not in directory.parents or not directory.is_dir():
            raise SystemExit(f"invalid or missing evidence directory: {relative}")
        document_name = str(record["document"])
        document_path = directory / document_name
        observed = json.loads(document_path.read_text(encoding="utf-8"))
        require_subset(observed, record.get("expected", {}))
        if "expected_stimulus_codes" in record:
            require_subset(
                codes(observed, "stimuli"),
                record["expected_stimulus_codes"],
                "$.stimulus_codes",
            )
        if "expected_violation_codes" in record:
            require_subset(
                codes(observed, "violations"),
                record["expected_violation_codes"],
                "$.violation_codes",
            )
        files: dict[str, str] = {}
        for path in sorted(item for item in directory.rglob("*") if item.is_file()):
            name = path.relative_to(directory).as_posix()
            digest = sha256_file(path)
            files[name] = digest
            aggregate.update(relative.as_posix().encode("utf-8"))
            aggregate.update(b"\0")
            aggregate.update(name.encode("utf-8"))
            aggregate.update(b"\0")
            aggregate.update(digest.encode("ascii"))
            aggregate.update(b"\n")
        adopted.append(
            {
                "path": relative.as_posix(),
                "document": document_name,
                "files": files,
            }
        )

    manifest = {
        "schema": "teeweaver-evidence-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "spec": args.spec.resolve().relative_to(PROJECT).as_posix(),
        "aggregate_sha256": aggregate.hexdigest(),
        "adopted_results": adopted,
    }
    if args.verify:
        recorded = json.loads(args.verify.read_text(encoding="utf-8"))
        valid = (
            isinstance(recorded, dict)
            and recorded.get("schema") == manifest["schema"]
            and recorded.get("spec") == manifest["spec"]
            and recorded.get("aggregate_sha256") == manifest["aggregate_sha256"]
            and recorded.get("adopted_results") == manifest["adopted_results"]
        )
        print(json.dumps({
            "valid": valid,
            "aggregate_sha256": manifest["aggregate_sha256"],
        }, indent=2))
        return 0 if valid else 1

    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(output)
    print(manifest["aggregate_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
