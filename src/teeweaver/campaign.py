from __future__ import annotations

import random
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping

from .events import Event


RETURN_CODES = (
    ("generic", 0xFFFF0000),
    ("access-denied", 0xFFFF0001),
    ("cancel", 0xFFFF0002),
    ("bad-parameters", 0xFFFF0006),
    ("item-not-found", 0xFFFF0008),
    ("not-supported", 0xFFFF000A),
    ("out-of-memory", 0xFFFF000C),
    ("communication", 0xFFFF000E),
    ("security", 0xFFFF000F),
    ("short-buffer", 0xFFFF0010),
)


@dataclass(frozen=True, slots=True)
class RpcSurface:
    func: int
    occurrences: int
    max_params: int
    memref_positions: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class FfaSurface:
    kind: str
    action: int | None
    occurrences: int
    carries_handle: bool


@dataclass(frozen=True, slots=True)
class FaultPlan:
    rule: str
    family: str
    func: int
    occurrence: int | None
    rationale: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RunAssessment:
    classification: str
    reasons: tuple[str, ...]
    new_semantic_states: tuple[str, ...]
    new_semantic_state_count: int
    status_delta: Mapping[str, Mapping[str, str | None]]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def inventory(events: Iterable[Event]) -> list[RpcSurface]:
    by_func: dict[int, dict[str, int]] = {}
    for event in events:
        if event.op != "rpc_issue" or event.get("func") is None:
            continue
        func = int(event.get("func"))
        state = by_func.setdefault(
            func, {"count": 0, "max_params": 0, "memref_mask": 0}
        )
        state["count"] += 1
        state["max_params"] = max(state["max_params"], int(event.get("num_params", 0)))
        state["memref_mask"] |= int(event.get("memref_mask", 0))
    return [
        RpcSurface(
            func,
            state["count"],
            state["max_params"],
            tuple(
                index
                for index in range(64)
                if state["memref_mask"] & (1 << index)
            ),
        )
        for func, state in sorted(by_func.items())
    ]


def _cut_points(count: int) -> list[int]:
    if count < 1:
        return []
    points = {1, count, max(1, count // 2)}
    if count >= 8:
        points.update({max(1, count // 4), max(1, (3 * count) // 4)})
    return sorted(points)


def plan_faults(
    events: Iterable[Event], *, seed: int, budget: int
) -> tuple[list[RpcSurface], list[FaultPlan]]:
    """Build an advisory-blind one-fault campaign from an observed RPC surface.

    Plans depend only on protocol function numbers, observed cardinalities, and
    generic error/timing classes. No source location, advisory, or vulnerable
    revision is an input.
    """

    if budget < 1:
        raise ValueError("budget must be positive")
    surfaces = inventory(events)
    candidates: list[FaultPlan] = []
    for surface in surfaces:
        for occurrence in _cut_points(surface.occurrences):
            candidates.append(
                FaultPlan(
                    rule=f"swap_pair:{surface.func}:{occurrence}",
                    family="cross-bind",
                    func=surface.func,
                    occurrence=occurrence,
                    rationale=(
                        "attempt one bounded exchange of two concurrently live "
                        "protocol-valid responses"
                    ),
                )
            )
            for delay_us in (1000, 100000):
                candidates.append(
                    FaultPlan(
                        rule=f"delay:{surface.func}:{occurrence}:{delay_us}",
                        family="delay",
                        func=surface.func,
                        occurrence=occurrence,
                        rationale="move a legal response across a scheduling boundary",
                    )
                )
            for name, value in RETURN_CODES:
                candidates.append(
                    FaultPlan(
                        rule=f"force_ret:{surface.func}:{occurrence}:0x{value:x}",
                        family="return-code",
                        func=surface.func,
                        occurrence=occurrence,
                        rationale=f"replace a legal REE result with generic {name}",
                    )
                )
            for param_index in surface.memref_positions:
                candidates.append(
                    FaultPlan(
                        rule=(
                            f"flip_memref:{surface.func}:{occurrence}:"
                            f"{param_index}:0:0x1"
                        ),
                        family="memref",
                        func=surface.func,
                        occurrence=occurrence,
                        rationale=(
                            "flip one response byte in an observed mapped memref "
                            "after the REE handler returns"
                        ),
                    )
                )

    rng = random.Random(seed)
    buckets: dict[str, list[FaultPlan]] = {
        "cross-bind": [],
        "delay": [],
        "return-code": [],
        "memref": [],
    }
    for candidate in candidates:
        buckets[candidate.family].append(candidate)
    for bucket in buckets.values():
        rng.shuffle(bucket)

    selected: list[FaultPlan] = []
    families = tuple(buckets)
    while len(selected) < budget and any(buckets.values()):
        for family in families:
            if buckets[family]:
                selected.append(buckets[family].pop())
                if len(selected) == budget:
                    break
    return surfaces, selected


def inventory_ffa(events: Iterable[Event]) -> list[FfaSurface]:
    """Inventory only public FF-A user-ABI operations observed at runtime."""

    counts: dict[tuple[str, int | None], int] = {}
    for event in events:
        if event.op == "ffa_direct_message":
            key = ("message", int(event.get("action", -1)))
        elif event.op == "ffa_reclaim_attempt":
            key = ("reclaim", None)
        else:
            continue
        counts[key] = counts.get(key, 0) + 1
    return [
        FfaSurface(
            kind=kind,
            action=action,
            occurrences=count,
            carries_handle=kind == "reclaim" or action in {5, 6},
        )
        for (kind, action), count in sorted(
            counts.items(), key=lambda item: (item[0][0], item[0][1] or -1)
        )
    ]


def plan_ffa_faults(
    events: Iterable[Event], *, seed: int, budget: int
) -> tuple[list[FfaSurface], list[FaultPlan]]:
    """Build a state-machine campaign from the observed FF-A ABI history.

    The planner knows only operation kinds, action numbers, handle-bearing
    relationships, and cardinalities. It contains no advisory names, source
    locations, or revision-specific trigger sequence.
    """

    if budget < 1:
        raise ValueError("budget must be positive")
    surfaces = inventory_ffa(events)
    candidates: list[FaultPlan] = []
    for surface in surfaces:
        target = "reclaim" if surface.kind == "reclaim" else str(surface.action)
        numeric = -1 if surface.action is None else surface.action
        for occurrence in _cut_points(surface.occurrences):
            for delay_us in (1000, 100000):
                candidates.append(
                    FaultPlan(
                        rule=f"ffa_delay:{target}:{occurrence}:{delay_us}",
                        family="ffa-delay",
                        func=numeric,
                        occurrence=occurrence,
                        rationale="move a legal FF-A transition across a schedule boundary",
                    )
                )
            candidates.append(
                FaultPlan(
                    rule=f"ffa_duplicate:{target}:{occurrence}",
                    family="ffa-duplicate",
                    func=numeric,
                    occurrence=occurrence,
                    rationale="repeat one protocol-valid transition without changing its bytes",
                )
            )
            if surface.carries_handle:
                candidates.append(
                    FaultPlan(
                        rule=f"ffa_flip_handle:{target}:{occurrence}:0x1",
                        family="ffa-handle",
                        func=numeric,
                        occurrence=occurrence,
                        rationale="substitute one bit of an observed FF-A memory handle",
                    )
                )

    rng = random.Random(seed)
    families = ("ffa-delay", "ffa-duplicate", "ffa-handle")
    buckets: dict[str, list[FaultPlan]] = {family: [] for family in families}
    for candidate in candidates:
        buckets[candidate.family].append(candidate)
    for bucket in buckets.values():
        rng.shuffle(bucket)
    selected: list[FaultPlan] = []
    while len(selected) < budget and any(buckets.values()):
        for family in families:
            if buckets[family]:
                selected.append(buckets[family].pop())
                if len(selected) == budget:
                    break
    return surfaces, selected


def assess_run(
    baseline: Mapping[str, Any],
    observed: Mapping[str, Any] | None,
    *,
    process_returncode: int,
) -> RunAssessment:
    """Classify an experiment without equating target symptoms with bugs.

    The ordering is deliberate: an invariant violation is a candidate even if
    the workload also fails; an observable workload delta is only a symptom;
    and a runner failure with no target evidence remains infrastructure noise.
    """

    if observed is None:
        return RunAssessment(
            classification="runner-failure",
            reasons=(f"experiment runner exited {process_returncode} without summary",),
            new_semantic_states=(),
            new_semantic_state_count=0,
            status_delta={},
        )

    baseline_states = set(baseline.get("semantic_state_ids", ()))
    observed_states = set(observed.get("semantic_state_ids", ()))
    all_new_states = tuple(sorted(observed_states - baseline_states))
    new_states = all_new_states[:64]
    new_state_count = len(all_new_states)

    baseline_status = {
        str(key): str(value) for key, value in baseline.get("statuses", {}).items()
    }
    observed_status = {
        str(key): str(value) for key, value in observed.get("statuses", {}).items()
    }
    status_delta: dict[str, dict[str, str | None]] = {}
    # Missing status files are not a target result: they commonly mean the
    # runner timed out before collecting the workload outcome. Only compare
    # statuses that both runs actually produced.
    for key in sorted(set(baseline_status) & set(observed_status)):
        before = baseline_status.get(key)
        after = observed_status.get(key)
        if before != after:
            status_delta[key] = {"baseline": before, "observed": after}

    violations = observed.get("violations", ())
    stimuli = observed.get("stimuli", ())
    target_symptoms = observed.get("target_symptoms", ())
    run_error = observed.get("run_error")
    if violations:
        reasons = [f"{len(violations)} accepted invariant violation(s)"]
        if status_delta:
            reasons.append("workload status differs from clean control")
        return RunAssessment(
            "violation-candidate",
            tuple(reasons),
            new_states,
            new_state_count,
            status_delta,
        )
    if target_symptoms:
        codes = sorted({
            str(item.get("code", "TARGET_FAILURE"))
            for item in target_symptoms
        })
        reasons = [
            "target emitted crash/panic evidence: " + ", ".join(codes),
            "symptom requires invariant, reachability, and impact validation",
        ]
        if run_error:
            reasons.append(f"runner also reported: {run_error}")
        return RunAssessment(
            "target-symptom", tuple(reasons), new_states,
            new_state_count, status_delta,
        )
    if status_delta:
        reasons = ["workload status differs from clean control"]
        if run_error:
            reasons.append(f"runner also reported: {run_error}")
        return RunAssessment(
            "behavioral-symptom",
            tuple(reasons),
            new_states,
            new_state_count,
            status_delta,
        )
    if run_error or process_returncode != 0:
        detail = str(run_error or f"runner exited {process_returncode}")
        return RunAssessment(
            "runner-failure", (detail,), new_states, new_state_count, {}
        )
    if stimuli:
        return RunAssessment(
            "stimulus-only",
            (f"{len(stimuli)} adversarial stimulus event(s), no accepted violation",),
            new_states,
            new_state_count,
            {},
        )
    if all_new_states:
        return RunAssessment(
            "semantic-novelty",
            (f"{new_state_count} semantic state(s) absent from clean control",),
            new_states,
            new_state_count,
            {},
        )
    return RunAssessment(
        "no-effect", ("no target-visible delta from clean control",), (), 0, {}
    )
