from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


DEFAULT_ROOTS = (
    ".github",
    ".gitignore",
    "CITATION.cff",
    "CHANGELOG.md",
    "LICENSE",
    "MANIFEST.in",
    "README.md",
    "RELEASE_NOTES.md",
    "SECURITY.md",
    "pyproject.toml",
    "docs",
    "examples",
    "instrumentation",
    "scenarios",
    "src",
    "tests",
    "tools",
)

EXCLUDED_PARTS = {
    "__pycache__",
    ".pytest_cache",
}

EXCLUDED_SUFFIXES = {
    ".pyc",
    ".so",
}

EXCLUDED_NAMES = {
    "test_driver",
    "storage_probe",
    "ffa_probe",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_frozen_files(project: Path, roots: Iterable[str] = DEFAULT_ROOTS):
    for root_name in roots:
        root = project / root_name
        candidates = [root] if root.is_file() else root.rglob("*")
        for path in candidates:
            if not path.is_file():
                continue
            relative = path.relative_to(project)
            if any(
                part in EXCLUDED_PARTS or part.endswith(".egg-info")
                for part in relative.parts
            ):
                continue
            if path.suffix in EXCLUDED_SUFFIXES or path.name in EXCLUDED_NAMES:
                continue
            yield relative


def aggregate_digest(files: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for name, value in sorted(files.items()):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(value.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def build_manifest(project: Path, *, label: str) -> dict[str, object]:
    files = {
        relative.as_posix(): sha256_file(project / relative)
        for relative in sorted(iter_frozen_files(project))
    }
    return {
        "schema": "teeweaver-freeze-v1",
        "label": label,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "aggregate_sha256": aggregate_digest(files),
        "files": files,
        "exclusions": {
            "known_case_registry": "evaluation/known_cases.json",
            "generated_results": "results/",
            "generated_artifacts": "artifacts/",
            "reason": (
                "generation, scheduling, and oracles are frozen before "
                "known-case evaluation; outputs are not inputs to the digest"
            ),
        },
    }


@dataclass(frozen=True, slots=True)
class Verification:
    valid: bool
    missing: tuple[str, ...]
    changed: tuple[str, ...]
    unexpected: tuple[str, ...]


def verify_manifest(project: Path, manifest: dict[str, object]) -> Verification:
    recorded = manifest.get("files")
    if not isinstance(recorded, dict):
        raise ValueError("manifest has no files object")
    expected = {str(name): str(value) for name, value in recorded.items()}
    observed = {
        relative.as_posix(): sha256_file(project / relative)
        for relative in sorted(iter_frozen_files(project))
    }
    missing = tuple(sorted(set(expected) - set(observed)))
    unexpected = tuple(sorted(set(observed) - set(expected)))
    changed = tuple(
        sorted(
            name
            for name in set(expected) & set(observed)
            if expected[name] != observed[name]
        )
    )
    aggregate_matches = manifest.get("aggregate_sha256") == aggregate_digest(expected)
    return Verification(
        valid=not missing and not unexpected and not changed and aggregate_matches,
        missing=missing,
        changed=changed,
        unexpected=unexpected,
    )


def read_manifest(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("freeze manifest must be an object")
    return value
