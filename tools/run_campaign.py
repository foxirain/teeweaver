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
from teeweaver.discovery import profile_runs  # noqa: E402
from teeweaver.discovery_index import NoveltyIndex  # noqa: E402
from teeweaver.elements import RunHistory  # noqa: E402
from teeweaver.state_machine import observe_boundaries  # noqa: E402
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


def profile_result(
    directory: Path, *, label: str, role: str, group: str,
    summary: dict[str, Any],
):
    trace_path = directory / "trace.jsonl"
    if not trace_path.is_file():
        return None
    history = RunHistory(
        label=label,
        role=role,
        group=group,
        path=str(directory),
        events=tuple(read_jsonl(trace_path)),
        summary=summary,
    )
    return profile_runs([history])[0][0]


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
    parser.add_argument(
        "--input-discovery-index", type=Path,
        help="optional prior novelty index for cross-campaign corpus retention",
    )
    parser.add_argument(
        "--novelty-stagnation", type=int, default=0,
        help=(
            "stop after this many consecutive low-novelty/duplicate runs; "
            "zero disables early stopping"
        ),
    )
    parser.add_argument(
        "--boundary-plateau", type=int, default=0,
        help=(
            "stop after this many consecutive fault runs add no normalized "
            "security-boundary tuple; zero disables this stop condition"
        ),
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
    if args.novelty_stagnation < 0:
        parser.error("--novelty-stagnation cannot be negative")
    if args.boundary_plateau < 0:
        parser.error("--boundary-plateau cannot be negative")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    campaign_dir = (args.output or PROJECT / "results" / f"campaign-{stamp}").resolve()
    campaign_dir.mkdir(parents=True, exist_ok=False)

    if args.input_discovery_index is not None:
        loaded_index = load_json(args.input_discovery_index.resolve())
        if loaded_index is None:
            parser.error("--input-discovery-index does not exist")
        novelty_index = NoveltyIndex.from_dict(loaded_index)
    else:
        novelty_index = NoveltyIndex()

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

        profile = profile_result(
            baseline_dir,
            label=f"{campaign_dir.name}/{baseline_dir.name}",
            role="control",
            group=args.workload,
            summary=baseline_run,
        )
        if profile is not None:
            novelty_index.ingest(profile)
            write_json(
                campaign_dir / "discovery-index.json", novelty_index.as_dict()
            )

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
    boundary_seen: set[str] = set()
    for baseline_dir in baseline_dirs:
        baseline_trace = baseline_dir / "trace.jsonl"
        if baseline_trace.is_file():
            boundary_seen.update(
                item.tuple.signature()
                for item in observe_boundaries(read_jsonl(baseline_trace))
            )
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
        "boundary_plateau": args.boundary_plateau,
        "derivation": derivation,
        "surface": [dataclasses.asdict(item) for item in surfaces],
        "faults": [item.as_dict() for item in plans],
    }
    write_json(campaign_dir / "plan.json", plan_record)

    results: list[dict[str, Any]] = []
    stagnant_runs = 0
    boundary_stagnant_runs = 0
    stopped_early = False
    stop_reason: str | None = None
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
        run_boundaries: set[str] = set()
        trace_path = run_dir / "trace.jsonl"
        if trace_path.is_file():
            run_boundaries = {
                item.tuple.signature()
                for item in observe_boundaries(read_jsonl(trace_path))
            }
        new_boundaries = run_boundaries - boundary_seen
        boundary_seen |= run_boundaries
        if new_boundaries:
            boundary_stagnant_runs = 0
        else:
            boundary_stagnant_runs += 1
        result = {
            "index": index,
            "fault": plan.as_dict(),
            "returncode": returncode,
            "result_dir": run_dir.name,
            "assessment": assessment.as_dict(),
            "event_count": observed.get("events") if observed else None,
            "stimulus_count": len(observed.get("stimuli", ())) if observed else None,
            "violation_count": len(observed.get("violations", ())) if observed else None,
            "boundary_tuples": len(run_boundaries),
            "new_boundary_tuples": len(new_boundaries),
            "boundary_plateau_streak": boundary_stagnant_runs,
        }
        if observed is not None:
            profile = profile_result(
                run_dir,
                label=f"{campaign_dir.name}/{run_dir.name}",
                role="treatment",
                group=args.workload,
                summary=observed,
            )
            if profile is not None:
                decision = novelty_index.ingest(profile)
                result["discovery"] = decision.as_dict()
                write_json(run_dir / "discovery-decision.json", decision.as_dict())
                write_json(
                    campaign_dir / "discovery-index.json", novelty_index.as_dict()
                )
                if decision.disposition.startswith("discard-"):
                    stagnant_runs += 1
                else:
                    stagnant_runs = 0
        results.append(result)
        write_json(run_dir / "assessment.json", result)
        print(
            f"    => {assessment.classification}; "
            f"boundary-new={len(new_boundaries)}",
            flush=True,
        )
        if (
            args.novelty_stagnation
            and stagnant_runs >= args.novelty_stagnation
        ):
            stop_reason = (
                f"semantic novelty saturated for {stagnant_runs} consecutive runs"
            )
            stopped_early = True
        elif (
            args.boundary_plateau
            and boundary_stagnant_runs >= args.boundary_plateau
        ):
            stop_reason = (
                "normalized boundary coverage plateaued for "
                f"{boundary_stagnant_runs} consecutive runs"
            )
            stopped_early = True
        if stopped_early:
            print(f"adaptive stop: {stop_reason}", flush=True)
            break

    counts: dict[str, int] = {}
    for item in results:
        classification = item["assessment"]["classification"]
        counts[classification] = counts.get(classification, 0) + 1
    campaign = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "complete-early-adaptive-stop" if stopped_early else "complete",
        "workload": args.workload,
        "seed": args.seed,
        "budget": args.budget,
        "executed": len(results),
        "stop_reason": stop_reason,
        "boundary_tuple_union": len(boundary_seen),
        "baseline": {
            "result_dirs": [path.name for path in baseline_dirs],
            "events_per_run": [item.get("events") for item in baselines],
            "semantic_state_union": len(baseline["semantic_state_ids"]),
            "statuses": baseline.get("statuses"),
        },
        "classification_counts": counts,
        "discovery": {
            "observed_runs": novelty_index.observed_runs,
            "retained_runs": len(novelty_index.retained_profiles),
            "index": "discovery-index.json",
            "early_stop_threshold": args.novelty_stagnation,
            "stopped_early": stopped_early,
            "boundary_plateau_threshold": args.boundary_plateau,
        },
        "results": results,
    }
    write_json(campaign_dir / "discovery-index.json", novelty_index.as_dict())
    write_json(campaign_dir / "campaign.json", campaign)
    print(campaign_dir, flush=True)
    return 1 if counts.get("violation-candidate", 0) else 0


if __name__ == "__main__":
    raise SystemExit(main())
