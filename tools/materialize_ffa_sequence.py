#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import uuid as uuid_module
from pathlib import Path
from typing import Any, Mapping


def load_proposal(path: Path, proposal_id: str) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("discovery report must contain a JSON object")
    experiments = value.get("experiments", value.get("experiment_proposals", value))
    if not isinstance(experiments, Mapping):
        raise ValueError("discovery report experiments must be an object")
    proposals = experiments.get("proposals", [])
    if not isinstance(proposals, list):
        raise ValueError("discovery report proposals must be a list")
    for proposal in proposals:
        if isinstance(proposal, Mapping) and proposal.get("proposal_id") == proposal_id:
            return proposal
    raise ValueError(f"proposal not found: {proposal_id}")


def parse_endpoint(value: str) -> tuple[str, str]:
    name, separator, uuid_text = value.partition("=")
    if (
        not separator
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,31}", name)
        or any(ch.isspace() for ch in value)
    ):
        raise ValueError("endpoint must be NAME=UUID")
    try:
        parsed = uuid_module.UUID(uuid_text)
    except ValueError as error:
        raise ValueError("endpoint UUID must be canonical hexadecimal UUID") from error
    if str(parsed) != uuid_text.lower():
        raise ValueError("endpoint UUID must be canonical hexadecimal UUID")
    return name, str(parsed)


def target_action(proposal: Mapping[str, Any], default: int) -> int:
    operation = str(proposal.get("target_boundary", {}).get("operation", ""))
    marker = ":action="
    if marker not in operation:
        return default
    action = int(operation.split(marker, 1)[1])
    if not 0 <= action < 2**64:
        raise ValueError("FF-A action must fit in an unsigned 64-bit value")
    return action


def materialize(proposal: Mapping[str, Any], endpoints: list[tuple[str, str]]) -> list[str]:
    family = str(proposal.get("family"))
    protocol = str(proposal.get("target_boundary", {}).get("protocol", ""))
    if not endpoints:
        raise ValueError("at least one --endpoint is required")
    if protocol != "ffa":
        raise ValueError(
            f"proposal targets protocol {protocol!r}, not FF-A; refusing to "
            "materialize it through the wrong adapter"
        )
    lines = [
        f"# proposal {json.dumps(str(proposal.get('proposal_id')))}",
        f"# family {json.dumps(family)}",
        "# Generated from a semantic relationship; this is an experiment, not a finding.",
    ]
    lines.extend(f"endpoint {name} {uuid}" for name, uuid in endpoints)
    a = endpoints[0][0]
    lines.append(f"ping {a}")

    if family == "cross-principal-identity-transposition":
        if len(endpoints) < 2:
            raise ValueError("cross-principal transposition requires two --endpoint values")
        b = endpoints[1][0]
        action = target_action(proposal, 5)
        lines.extend((
            f"ping {b}",
            f"share owner_handle {a} 4096",
            f"share peer_control {b} 4096",
            f"send {a} 5 owner_handle",
            f"send {b} {action} owner_handle",
            f"ping {a}",
            f"ping {b}",
        ))
    elif family == "lifecycle-epoch-crossing":
        action = target_action(proposal, 5)
        lines.extend((
            f"share stale_handle {a} 4096",
            f"send {a} 5 stale_handle",
            f"send {a} 6 stale_handle",
            "reclaim stale_handle",
            f"send {a} {action} stale_handle",
            f"ping {a}",
        ))
    elif family == "duplicate-terminal-transition":
        operation = str(proposal.get("target_boundary", {}).get("operation", ""))
        lines.extend((
            f"share terminal_handle {a} 4096",
            f"send {a} 5 terminal_handle",
            f"send {a} 6 terminal_handle",
        ))
        if operation.startswith("ffa_reclaim_attempt"):
            lines.extend(("reclaim terminal_handle", "reclaim terminal_handle"))
        elif operation.startswith("ffa_relinquish"):
            lines.append(f"send {a} 6 terminal_handle")
        else:
            raise ValueError(f"unsupported FF-A terminal operation: {operation}")
        lines.append(f"ping {a}")
    else:
        raise ValueError(
            f"family {family!r} cannot be faithfully materialized by the current "
            "FF-A adapter; implement the requested adapter instead of approximating it"
        )
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Materialize a supported semantic proposal as an FF-A sequence plan"
    )
    parser.add_argument("discovery_report", type=Path)
    parser.add_argument("proposal_id")
    parser.add_argument(
        "--endpoint", action="append", default=[], metavar="NAME=UUID",
        help="reachable existing Secure Partition; repeat for cross-principal plans",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        proposal = load_proposal(args.discovery_report, args.proposal_id)
        endpoints = [parse_endpoint(value) for value in args.endpoint]
        if len({name for name, _ in endpoints}) != len(endpoints):
            raise ValueError("endpoint names must be unique")
        lines = materialize(proposal, endpoints)
    except ValueError as error:
        parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
