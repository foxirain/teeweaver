#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from teeweaver.campaign import assess_run, plan_faults, plan_ffa_faults  # noqa: E402
from teeweaver.trace import read_jsonl  # noqa: E402
from teeweaver.workloads import load_workloads  # noqa: E402


WORKLOADS = load_workloads(PROJECT / "scenarios/workloads.json")


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"expected object in {path}")
    return value


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def run_experiment(
    *,
    optee_root: Path,
    workload: str,
    fault: str,
    output: Path,
) -> tuple[int, dict[str, Any] | None]:
    command = [
        sys.executable,
        str(PROJECT / "tools/run_qemu_experiment.py"),
        "--optee-root",
        str(optee_root),
        "--workload",
        workload,
        "--fault",
        fault,
        "--output",
        str(output),
    ]
    completed = subprocess.run(
        command,
        cwd=PROJECT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    output.mkdir(parents=True, exist_ok=True)
    (output / "runner.log").write_text(completed.stdout, encoding="utf-8")
    (output / "runner-command.json").write_text(
        json.dumps(command, indent=2) + "\n", encoding="utf-8"
    )
    return completed.returncode, load_json(output / "summary.json")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run an advisory-blind TEEWeaver fault campaign"
    )
    parser.add_argument(
        "--optee-root",
        type=Path,
        default=PROJECT.parent / "optee-qemu-v8",
    )
    parser.add_argument(
        "--workload",
        choices=tuple(sorted(WORKLOADS)),
        default="load-ta-swap",
    )
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--budget", type=int, default=12)
    parser.add_argument(
        "--baseline-runs",
        type=int,
        default=3,
        help="clean executions whose state union defines ordinary schedule variance",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if not WORKLOADS[args.workload].campaign_eligible:
        parser.error(
            f"workload {args.workload!r} has no stable clean baseline and is "
            "therefore excluded from automated vulnerability campaigns"
        )

    if args.budget < 1:
        parser.error("--budget must be positive")
    if args.baseline_runs < 1:
        parser.error("--baseline-runs must be positive")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    campaign_dir = (args.output or PROJECT / "results" / f"campaign-{stamp}").resolve()
    campaign_dir.mkdir(parents=True, exist_ok=False)

    baselines: list[dict[str, Any]] = []
    baseline_dirs: list[Path] = []
    for index in range(1, args.baseline_runs + 1):
        baseline_dir = campaign_dir / f"baseline-{index:03d}"
        baseline_dirs.append(baseline_dir)
        print(
            f"[baseline {index}/{args.baseline_runs}] workload={args.workload}",
            flush=True,
        )
        baseline_rc, baseline_run = run_experiment(
            optee_root=args.optee_root.resolve(),
            workload=args.workload,
            fault="none",
            output=baseline_dir,
        )
        if (
            baseline_rc != 0
            or baseline_run is None
            or baseline_run.get("run_error")
        ):
            write_json(
                campaign_dir / "campaign.json",
                {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "status": "baseline-failed",
                    "failed_baseline": index,
                    "baseline_returncode": baseline_rc,
                    "baseline": baseline_run,
                },
            )
            print(
                f"baseline failed; inspect {baseline_dir / 'runner.log'}",
                flush=True,
            )
            return 2
        baselines.append(baseline_run)

    baseline_violations = [item.get("violations", []) for item in baselines]
    if any(baseline_violations):
        write_json(
            campaign_dir / "campaign.json",
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "status": "baseline-oracle-dirty",
                "reason": (
                    "at least one clean run violates an oracle; campaign "
                    "classification is disabled until instrumentation/model "
                    "identity is corrected"
                ),
                "baseline_violation_codes": [
                    [str(value.get("code")) for value in violations]
                    for violations in baseline_violations
                ],
            },
        )
        print("clean controls violate an oracle; refusing campaign", flush=True)
        return 2

    baseline_statuses = [item.get("statuses", {}) for item in baselines]
    if any(status != baseline_statuses[0] for status in baseline_statuses[1:]):
        write_json(
            campaign_dir / "campaign.json",
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "status": "unstable-baseline",
                "baseline_statuses": baseline_statuses,
            },
        )
        print("clean controls have unstable workload statuses", flush=True)
        return 2

    baseline = dict(baselines[0])
    baseline["semantic_state_ids"] = sorted(
        {
            state
            for baseline_run in baselines
            for state in baseline_run.get("semantic_state_ids", ())
        }
    )
    trace = read_jsonl(baseline_dirs[0] / "trace.jsonl")
    workload = WORKLOADS[args.workload]
    if workload.ffa_trace:
        surfaces, plans = plan_ffa_faults(
            trace, seed=args.seed, budget=args.budget
        )
        derivation = "observed FF-A operation/action/cardinality only"
    else:
        surfaces, plans = plan_faults(trace, seed=args.seed, budget=args.budget)
        derivation = "observed RPC function/cardinality only"
    plan_record = {
        "seed": args.seed,
        "budget": args.budget,
        "baseline_runs": args.baseline_runs,
        "derivation": derivation,
        "surface": [dataclasses.asdict(item) for item in surfaces],
        "faults": [item.as_dict() for item in plans],
    }
    write_json(campaign_dir / "plan.json", plan_record)

    results: list[dict[str, Any]] = []
    for index, plan in enumerate(plans, 1):
        run_dir = campaign_dir / f"run-{index:03d}"
        print(f"[{index}/{len(plans)}] {plan.rule}", flush=True)
        returncode, observed = run_experiment(
            optee_root=args.optee_root.resolve(),
            workload=args.workload,
            fault=plan.rule,
            output=run_dir,
        )
        assessment = assess_run(
            baseline, observed, process_returncode=returncode
        )
        result = {
            "index": index,
            "fault": plan.as_dict(),
            "returncode": returncode,
            "result_dir": run_dir.name,
            "assessment": assessment.as_dict(),
            "event_count": observed.get("events") if observed else None,
            "stimulus_count": len(observed.get("stimuli", ())) if observed else None,
            "violation_count": len(observed.get("violations", ())) if observed else None,
        }
        results.append(result)
        write_json(run_dir / "assessment.json", result)
        print(f"    => {assessment.classification}", flush=True)

    counts: dict[str, int] = {}
    for item in results:
        classification = item["assessment"]["classification"]
        counts[classification] = counts.get(classification, 0) + 1
    campaign = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "complete",
        "workload": args.workload,
        "seed": args.seed,
        "budget": args.budget,
        "baseline": {
            "result_dirs": [path.name for path in baseline_dirs],
            "events_per_run": [item.get("events") for item in baselines],
            "semantic_state_union": len(baseline["semantic_state_ids"]),
            "statuses": baseline.get("statuses"),
        },
        "classification_counts": counts,
        "results": results,
    }
    write_json(campaign_dir / "campaign.json", campaign)
    print(campaign_dir, flush=True)
    return 1 if counts.get("violation-candidate", 0) else 0


if __name__ == "__main__":
    raise SystemExit(main())
