from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .events import Event
from .secure_trace import read_secure_log
from .trace import read_jsonl


@dataclass(frozen=True, slots=True)
class RunHistory:
    """One execution history plus the externally visible result of that run."""

    label: str
    role: str
    group: str
    path: str
    events: tuple[Event, ...]
    summary: Mapping[str, Any] = field(default_factory=dict)

    @property
    def outcome(self) -> tuple[Any, ...]:
        statuses = tuple(sorted((str(k), str(v)) for k, v in self.summary.get(
            "statuses", {}
        ).items()))
        violations = tuple(sorted(
            str(item.get("code")) for item in self.summary.get("violations", [])
            if isinstance(item, Mapping)
        ))
        error = self.summary.get("run_error")
        error_kind = str(error).split(":", 1)[0] if error else None
        return statuses, violations, error_kind

    @property
    def states(self) -> frozenset[str]:
        return frozenset(str(x) for x in self.summary.get(
            "semantic_state_ids", []
        ))


@dataclass(frozen=True, slots=True)
class Element:
    """A reusable dynamic fact or hypothesis, deliberately not a vulnerability."""

    element_id: str
    kind: str
    title: str
    score: int
    confidence: str
    claim: str
    evidence: tuple[Mapping[str, Any], ...]
    why_dynamic: str
    caveats: tuple[str, ...]
    falsifiers: tuple[str, ...]
    next_experiments: tuple[str, ...]
    root_cause_hints: tuple[str, ...]
    not_a_vulnerability: bool = True

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["evidence"] = [dict(item) for item in self.evidence]
        return value


def _element(
    kind: str,
    title: str,
    score: int,
    confidence: str,
    claim: str,
    evidence: Sequence[Mapping[str, Any]],
    why_dynamic: str,
    caveats: Sequence[str],
    falsifiers: Sequence[str],
    next_experiments: Sequence[str],
    root_cause_hints: Sequence[str],
) -> Element:
    stable = json.dumps(
        {"kind": kind, "claim": claim, "evidence": list(evidence)},
        sort_keys=True,
        separators=(",", ":"),
    )
    suffix = hashlib.sha256(stable.encode()).hexdigest()[:12]
    return Element(
        f"{kind}-{suffix}", kind, title, max(0, min(100, score)), confidence,
        claim, tuple(evidence), why_dynamic, tuple(caveats), tuple(falsifiers),
        tuple(next_experiments), tuple(root_cause_hints),
    )


def _principal(event: Event) -> str:
    return str(event.get("process", event.actor))


def _event_ref(run: RunHistory, event: Event, **extra: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "run": run.label,
        "seq": event.seq,
        "op": event.op,
        "actor": event.actor,
    }
    for key in ("process", "object", "generation", "receiver", "action",
                "func", "ioctl_result", "ioctl_errno", "call", "fault",
                "source", "order_domain", "source_line", "trace_rule",
                "trace_confidence"):
        if event.get(key) is not None:
            value[key] = event.get(key)
    value.update(extra)
    return value


def _action(event: Event) -> str:
    if event.get("action") is not None:
        return f"{event.op}[action={event.get('action')}]"
    if event.get("func") is not None:
        return f"{event.op}[func={event.get('func')}]"
    if event.get("kind") is not None:
        return f"{event.op}[kind={event.get('kind')}]"
    return event.op


def _interesting(event: Event) -> bool:
    return event.op.startswith(("ffa_", "rpc_", "shm_", "operation_", "storage_")) \
        or event.op in {"reset", "object_verify", "object_consume"}


def mine_hidden_global_resources(runs: Sequence[RunHistory]) -> list[Element]:
    evidence: list[dict[str, Any]] = []
    scopes: set[str] = set()
    for run in runs:
        by_object: dict[str, list[Event]] = defaultdict(list)
        shares: list[Event] = []
        for event in run.events:
            if event.get("object") is not None:
                by_object[str(event.get("object"))].append(event)
            if event.op in {"ffa_share", "shm_register"}:
                shares.append(event)
        for obj, events in by_object.items():
            principals = {_principal(event) for event in events}
            if len(principals) > 1:
                scopes.add("identity-visible-across-processes")
                evidence.extend(
                    _event_ref(run, event, relationship="same-object-cross-principal")
                    for event in events[:4]
                )
        # Consecutive handles issued to separate processes are evidence for one
        # allocator domain even though the identities themselves differ.
        numeric = []
        for event in shares:
            try:
                numeric.append((int(str(event.get("object")), 16), event))
            except (TypeError, ValueError):
                pass
        numeric.sort(key=lambda item: item[0])
        for (left, a), (right, b) in zip(numeric, numeric[1:]):
            if _principal(a) != _principal(b) and right - left == 1:
                scopes.add("cross-process-handle-allocation")
                evidence.extend((
                    _event_ref(run, a, relationship="adjacent-global-allocation"),
                    _event_ref(run, b, relationship="adjacent-global-allocation"),
                ))
                break
    if not evidence:
        return []
    return [_element(
        "hidden-global-resource", "Resource identity exceeds an actor boundary",
        78 if "identity-visible-across-processes" in scopes else 68,
        "high" if "identity-visible-across-processes" in scopes else "medium",
        "Observed resource allocation or identity is shared across principals; "
        "per-process reasoning is therefore incomplete.",
        evidence[:12],
        "The scope is inferred from identities issued and consumed by independent "
        "runtime principals, not from the declaration site of a global variable.",
        ("Adjacent numeric handles can be an implementation convention rather than a security boundary.",),
        ("Show that independent processes use disjoint allocators after controlling for boot order.",),
        ("Run three clients with staggered allocation/free and measure handle reuse and contention.",
         "Perturb one client while holding the other clients byte-identical."),
        ("FF-A handle allocator and endpoint dispatch state",
         "driver-global IDR/xarray or SPMC-global object table"),
    )]


def mine_ownership_transfer(runs: Sequence[RunHistory]) -> list[Element]:
    evidence: list[dict[str, Any]] = []
    for run in runs:
        for event in run.events:
            if event.op not in {"ffa_share", "ffa_retrieve", "ffa_access",
                                "ffa_relinquish", "shm_use"}:
                continue
            owner = event.get("owner")
            receiver = event.get("receiver")
            if owner is not None and receiver is not None and str(owner) != str(receiver):
                evidence.append(_event_ref(
                    run, event, relationship="owner-to-receiver",
                    owner=owner, receiver=receiver,
                ))
    if not evidence:
        return []
    return [_element(
        "ownership-transfer", "One object crosses owner and receiver domains",
        80, "high",
        "The runtime history contains an explicit owner-to-receiver handoff whose "
        "authorization and lifetime must be checked at both ends.",
        evidence[:16],
        "Ownership is a temporal relationship: share, retrieve, access, relinquish, "
        "and reclaim occur in different protection domains.",
        ("A handoff is expected protocol behavior and is not evidence of unauthorized access.",),
        ("Demonstrate that owner and receiver are aliases of the same security principal.",),
        ("Mutate receiver identity between share and retrieve.",
         "Race relinquish/reclaim against receiver access and check both memory and metadata."),
        ("SPMC memory transaction ownership checks", "receiver-binding lifetime table"),
    )]


def mine_aba_cycles(runs: Sequence[RunHistory]) -> list[Element]:
    evidence: list[dict[str, Any]] = []
    for run in runs:
        by_object: dict[str, list[Event]] = defaultdict(list)
        for event in run.events:
            if event.get("object") is not None:
                by_object[str(event.get("object"))].append(event)
        for obj, events in by_object.items():
            generations = sorted({int(event.get("generation", 0)) for event in events})
            if len(generations) < 2:
                continue
            sample = [event for event in events if int(event.get("generation", 0))
                      in {generations[0], generations[-1]}]
            evidence.extend(
                _event_ref(run, event, relationship="identity-reused",
                           generations=generations[:8]) for event in sample[:6]
            )
    if not evidence:
        return []
    return [_element(
        "aba-reuse-cycle", "A visible identity is reused across lifetimes",
        85, "high",
        "At least one externally visible object identity returned after release/reclaim "
        "with a later generation, creating an ABA-sensitive state dimension.",
        evidence[:18],
        "Reuse requires history; a source snapshot cannot establish that an old and new "
        "lifetime collide in an actual allocator execution.",
        ("Generation is instrumentation metadata; consumers may already bind equivalent kernel metadata.",),
        ("Show that every consumer rejects an old generation even when the raw handle is reused.",),
        ("Delay a generation-N operation until generation N+1 owns the same identity.",
         "Replay stale retrieve/access/reply bytes after reuse."),
        ("raw handle lookup without generation", "free-list/ID allocator reuse window"),
    )]


def mine_failure_residue(runs: Sequence[RunHistory]) -> list[Element]:
    evidence: list[dict[str, Any]] = []
    cleanup_ops = {"reset", "ffa_relinquish", "ffa_reclaim", "shm_release",
                   "session_close", "operation_cancel"}
    for run in runs:
        for index, failed in enumerate(run.events):
            failed_result = failed.get("ioctl_result")
            is_failure = (failed_result is not None and int(failed_result) < 0) \
                or failed.op == "operation_fail"
            if not is_failure:
                continue
            obj = failed.get("object")
            receiver = failed.get("receiver")
            for later in run.events[index + 1:index + 65]:
                if later.op in cleanup_ops and (
                    obj is None or later.get("object") in {None, obj}
                ):
                    break
                same = obj is not None and later.get("object") == obj
                if not same and receiver is not None:
                    same = later.get("receiver") == receiver
                accepted = later.op in {"ffa_retrieve", "ffa_access", "ffa_share",
                                        "shm_use", "operation_complete"}
                if same and accepted:
                    evidence.extend((
                        _event_ref(run, failed, relationship="failed-transition"),
                        _event_ref(run, later, relationship="post-failure-state-use"),
                    ))
                    break
    if not evidence:
        return []
    return [_element(
        "failure-residual-state", "Execution continues through state touched by a failed transition",
        72, "medium",
        "A failed transition is followed by use of the same object or endpoint before an "
        "observed compensating transition, making failure atomicity a testable hypothesis.",
        evidence[:16],
        "Only execution history reveals whether cleanup actually occurred before later use.",
        ("The failing layer may have made no mutation, or cleanup may be invisible to this trace level.",),
        ("Instrument the lower layer and prove the failed call leaves the pre-call state byte-for-byte intact.",),
        ("Snapshot relevant metadata before failure and after the next accepted operation.",
         "Repeat with the next operation redirected to a different actor."),
        ("error unwind paths", "partial reference-count or binding updates"),
    )]


def mine_serialization_domains(runs: Sequence[RunHistory]) -> list[Element]:
    evidence: list[dict[str, Any]] = []
    for run in runs:
        principals = {_principal(event) for event in run.events
                      if event.op.startswith("ffa_")}
        if len(principals) < 2:
            continue
        calls = [event for event in run.events if event.op == "ffa_direct_message"]
        for failed in calls:
            if int(failed.get("ioctl_result", 0)) >= 0:
                continue
            for successful in calls:
                if successful is failed or int(successful.get("ioctl_result", -1)) < 0:
                    continue
                if _principal(successful) == _principal(failed):
                    continue
                if successful.get("action") != failed.get("action"):
                    continue
                evidence.extend((
                    _event_ref(run, failed, relationship="cross-principal-contention"),
                    _event_ref(run, successful, relationship="cross-principal-contention"),
                ))
                break
            if evidence:
                break
    if not evidence:
        return []
    errnos = {item.get("ioctl_errno") for item in evidence if item.get("ioctl_errno")}
    return [_element(
        "hidden-serialization-domain", "Independent endpoint calls share a serialization domain",
        82 if errnos else 74, "high" if errnos else "medium",
        "Concurrent calls from distinct processes/endpoints show mutually exclusive success "
        "and failure for the same action, indicating serialization above the apparent endpoint scope.",
        evidence[:16],
        "The shared lock/slot is inferred from cross-process scheduling outcomes rather than "
        "from a syntactic lock declaration.",
        ("Failures may be endpoint-local retry behavior unless timing correlation is reproduced.",),
        ("Show the same failure distribution when calls do not overlap.",),
        ("Sweep overlap from 0 to 100% and correlate EBUSY with in-flight calls.",
         "Use three endpoints to distinguish one global slot from per-endpoint slots."),
        ("arm_ffa_user transaction serialization", "SPMC direct-message in-flight state"),
    )]


def _run_orders(run: RunHistory, window: int = 12) -> dict[tuple[str, str], list[tuple[Event, Event]]]:
    events = [event for event in run.events if _interesting(event)]
    orders: dict[tuple[str, str], list[tuple[Event, Event]]] = defaultdict(list)
    for index, first in enumerate(events):
        for second in events[index + 1:index + 1 + window]:
            if _principal(first) == _principal(second):
                continue
            left, right = _action(first), _action(second)
            if left == right:
                continue
            orders[(left, right)].append((first, second))
    return orders


def mine_non_commutative_pairs(runs: Sequence[RunHistory]) -> list[Element]:
    by_group: dict[str, list[RunHistory]] = defaultdict(list)
    for run in runs:
        by_group[run.group].append(run)
    candidates: list[tuple[int, Element]] = []
    for group, members in by_group.items():
        observed = [(run, _run_orders(run)) for run in members]
        signatures = set().union(*(set(orders) for _, orders in observed))
        for left, right in sorted(signatures):
            forward = [(run, orders[(left, right)][0]) for run, orders in observed
                       if (left, right) in orders]
            reverse = [(run, orders[(right, left)][0]) for run, orders in observed
                       if (right, left) in orders]
            if not forward or not reverse:
                continue
            differing = [(a, ap, b, bp) for a, ap in forward for b, bp in reverse
                         if a.outcome != b.outcome]
            if not differing:
                continue
            a, ap, b, bp = differing[0]
            evidence = [
                _event_ref(a, ap[0], relationship="before", paired_with=left),
                _event_ref(a, ap[1], relationship="after", paired_with=right,
                           outcome=repr(a.outcome)),
                _event_ref(b, bp[0], relationship="before", paired_with=right),
                _event_ref(b, bp[1], relationship="after", paired_with=left,
                           outcome=repr(b.outcome)),
            ]
            support = len(forward) + len(reverse)
            candidates.append((support, _element(
                "non-commutative-action-pair",
                f"Order-sensitive candidate: {left} versus {right}",
                min(82, 55 + support * 2), "medium",
                f"Within corpus group {group!r}, both {left}→{right} and {right}→{left} "
                "occur, and the observed order co-varies with at least one externally visible "
                "outcome. This nominates a commutativity experiment; it does not yet establish "
                "that ordering caused the delta.",
                evidence,
                "Commutativity is a property of multiple schedules, not either source path alone.",
                ("Different injected faults or unobserved inputs may explain the outcome delta.",),
                ("Reproduce both orders with identical bytes, seed, and fault plan except scheduling.",),
                ("Add a deterministic barrier immediately before the two actions.",
                 "Run AB and BA schedules repeatedly and compare state snapshots."),
                ("shared state updated by both transitions", "missing ordering/transaction boundary"),
            )))
    return [item for _, item in sorted(candidates, key=lambda x: (-x[0], x[1].element_id))[:8]]


def mine_reset_survivors(runs: Sequence[RunHistory]) -> list[Element]:
    elements: list[Element] = []
    for run in runs:
        reset_indexes = [i for i, event in enumerate(run.events) if event.op == "reset"]
        for reset_index in reset_indexes:
            before = [event for event in run.events[:reset_index]
                      if event.op == "storage_ack"]
            after = [event for event in run.events[reset_index + 1:]
                     if event.op == "storage_observe"]
            for ack in before[-4:]:
                for observed in after[:4]:
                    if ack.get("key") != observed.get("key"):
                        continue
                    same = ack.get("digest") == observed.get("digest")
                    reset = run.events[reset_index]
                    claim = (
                        "An acknowledged storage value remains observable across reset."
                        if same else
                        "The post-reset value differs from the last acknowledged value; reset "
                        "does not by itself preserve freshness."
                    )
                    elements.append(_element(
                        "reset-surviving-state", "State crosses a reset boundary",
                        92 if not same else 82, "high", claim,
                        (_event_ref(run, ack, relationship="pre-reset-ack"),
                         _event_ref(run, reset, relationship="reset-boundary"),
                         _event_ref(run, observed, relationship="post-reset-observation",
                                    digest_matches=same)),
                        "Reset persistence is only visible by comparing epochs and acknowledged values.",
                        ("Persistence is expected; only a freshness mismatch suggests rollback exposure.",),
                        ("Bind the value to monotonic trusted state and reproduce a fresh value after replay.",),
                        ("Repeat across cold boot, warm reset, REE image replay, and secure-storage key rotation.",),
                        ("rollback protection metadata", "epoch/monotonic-counter binding"),
                    ))
    return elements


def mine_non_terminating_transitions(runs: Sequence[RunHistory]) -> list[Element]:
    buckets: dict[tuple[str, str, str], list[tuple[RunHistory, Event]]] = defaultdict(list)
    for run in runs:
        issues = {str(event.get("call")): event for event in run.events
                  if event.op == "ffa_call_issue" and event.get("call") is not None}
        completions = {str(event.get("call")) for event in run.events
                       if event.op in {"ffa_direct_message", "ffa_reclaim_attempt"}
                       and event.get("call") is not None}
        unmatched = [event for call, event in issues.items() if call not in completions]
        for event in unmatched:
            key = (str(event.get("target", "unknown")),
                   str(event.get("action", "unknown")),
                   str(event.get("receiver", "unknown")))
            buckets[key].append((run, event))
    elements: list[Element] = []
    for (target, action, receiver), observations in sorted(buckets.items()):
        evidence = [_event_ref(run, event, relationship="unmatched-issue")
                    for run, event in observations[:12]]
        # A completed control for the same abstract transition shows that the
        # issue marker itself does not mechanically make the call hang.
        observation_groups = {run.group for run, _ in observations}
        for run in runs:
            if run.group not in observation_groups:
                continue
            completed = next((event for event in run.events
                              if event.op in {"ffa_direct_message", "ffa_reclaim_attempt"}
                              and str(event.get("action")) == action
                              and str(event.get("receiver")) == receiver), None)
            if completed is not None:
                evidence.append(_event_ref(run, completed,
                                           relationship="completed-control"))
                break
        run_count = len({run.label for run, _ in observations})
        elements.append(_element(
            "non-terminating-transition", "A protocol transition has no observed completion",
            94 if run_count >= 2 else 86, "high",
            f"The {target} action {action} to receiver {receiver} crossed its issue point "
            f"but produced no return event in {run_count} independent run(s) before the "
            "bounded executions timed out.",
            evidence,
            "A pre-call marker is required; post-return tracing alone makes hangs invisible.",
            ("The runner may have terminated the VM before a merely slow call completed.",),
            ("Extend the deadline and show every issue receives a matching completion.",),
            ("Re-run with bounded deadlines and capture kernel/SP stacks at timeout.",
             "Vary the competing endpoint to localize the blocking domain."),
            ("unbounded wait or lost wakeup", "cross-endpoint direct-message serialization"),
        ))
    return elements


def mine_state_aliases(runs: Sequence[RunHistory]) -> list[Element]:
    by_group_outcome: dict[tuple[str, tuple[Any, ...]], list[RunHistory]] = defaultdict(list)
    for run in runs:
        if run.states:
            by_group_outcome[(run.group, run.outcome)].append(run)
    candidates: list[tuple[float, Element]] = []
    for (group, outcome), members in by_group_outcome.items():
        for index, left in enumerate(members):
            for right in members[index + 1:]:
                union = left.states | right.states
                if not union:
                    continue
                similarity = len(left.states & right.states) / len(union)
                unique = len(left.states ^ right.states)
                if similarity >= 0.80 or unique < 3:
                    continue
                evidence = ({
                    "run": left.label,
                    "outcome": repr(outcome),
                    "semantic_states": len(left.states),
                    "unique_against_peer": len(left.states - right.states),
                }, {
                    "run": right.label,
                    "outcome": repr(outcome),
                    "semantic_states": len(right.states),
                    "unique_against_peer": len(right.states - left.states),
                    "jaccard_similarity": round(similarity, 4),
                })
                candidates.append((similarity, _element(
                    "state-aliasing", "Same visible result masks different internal histories",
                    min(90, 65 + min(unique, 25)), "high" if similarity < 0.5 else "medium",
                    f"Two runs in group {group!r} have the same status/violation outcome but "
                    f"their semantic-state sets differ by {unique} states.",
                    evidence,
                    "The alias is discovered by comparing histories that collapse to the same exit status.",
                    ("Semantic-state coverage may include benign scheduling variation.",),
                    ("Show that the divergent states disappear after canonicalizing all relevant identities and timing.",),
                    ("Use the unique-state prefixes as targets for schedule replay and state snapshotting.",
                     "Add an observation after the nominally identical completion point."),
                    ("hidden state omitted from public result", "schedule-sensitive cache/refcount state"),
                )))
    return [item for _, item in sorted(candidates, key=lambda x: (x[0], x[1].element_id))[:8]]


def _split_order_domains(runs: Sequence[RunHistory]) -> list[RunHistory]:
    """Split histories for miners that depend on a trustworthy total order."""

    split: list[RunHistory] = []
    for run in runs:
        domains: dict[str, list[Event]] = defaultdict(list)
        for event in run.events:
            domains[str(event.get("order_domain", "default"))].append(event)
        for domain, events in sorted(domains.items()):
            split.append(RunHistory(
                run.label, run.role, run.group, f"{run.path}#{domain}",
                tuple(events), run.summary,
            ))
    return split


def mine_elements(runs: Sequence[RunHistory]) -> list[Element]:
    unordered_miners = (
        mine_hidden_global_resources,
        mine_ownership_transfer,
        mine_aba_cycles,
        mine_state_aliases,
    )
    ordered_miners = (
        mine_non_commutative_pairs,
        mine_failure_residue,
        mine_serialization_domains,
        mine_reset_survivors,
        mine_non_terminating_transitions,
    )
    ordered_runs = _split_order_domains(runs)
    elements = [
        element for miner in unordered_miners for element in miner(runs)
    ]
    elements.extend(
        element for miner in ordered_miners for element in miner(ordered_runs)
    )
    return sorted(elements, key=lambda item: (-item.score, item.kind, item.element_id))


def _load_one(
    project: Path, record: Mapping[str, Any], *, secure_logs: bool = False,
) -> list[RunHistory]:
    relative = Path(str(record["path"]))
    path = (project / relative).resolve()
    if project not in path.parents and path != project:
        raise ValueError(f"corpus path escapes project: {relative}")
    label = str(record.get("label", relative.as_posix()))
    role = str(record.get("role", "diagnostic"))
    group = str(record.get("group", label))
    expand = bool(record.get("expand", False))
    if expand:
        histories: list[RunHistory] = []
        for summary_path in sorted(path.glob("*/summary.json")):
            child = summary_path.parent
            child_role = "control" if child.name.startswith("baseline") else role
            child_record: dict[str, Any] = {
                "path": child.relative_to(project).as_posix(),
                "label": f"{label}/{child.name}",
                "role": child_role,
                "group": group,
            }
            if "secure_log" in record:
                child_record["secure_log"] = record["secure_log"]
            histories.extend(_load_one(
                project, child_record, secure_logs=secure_logs,
            ))
        return histories
    if path.is_file():
        trace_path = path
        directory = path.parent
    else:
        trace_path = path / str(record.get("trace", "trace.jsonl"))
        directory = path
    if not trace_path.is_file():
        raise ValueError(f"missing corpus trace: {trace_path}")
    summary_path = directory / str(record.get("summary", "summary.json"))
    summary: dict[str, Any] = {}
    if summary_path.is_file():
        loaded = json.loads(summary_path.read_text(encoding="utf-8"))
        if isinstance(loaded, Mapping):
            summary = dict(loaded)
    normal_events = []
    for event in read_jsonl(trace_path):
        attrs = dict(event.attrs)
        attrs.setdefault("source", "normal-jsonl")
        attrs.setdefault("order_domain", "normal-jsonl")
        normal_events.append(Event(event.seq, event.op, event.actor, attrs))

    secure_setting = record.get("secure_log")
    secure_path: Path | None = None
    if secure_setting is not False and (secure_logs or secure_setting is not None):
        if isinstance(secure_setting, str):
            secure_path = (directory / secure_setting).resolve()
            if project not in secure_path.parents and secure_path != project:
                raise ValueError(
                    f"secure log path escapes project: {secure_setting}"
                )
        else:
            secure_path = directory / "secure.log"
    secure_events: list[Event] = []
    if secure_path is not None and secure_path.is_file():
        parsed, stats = read_secure_log(secure_path)
        secure_events.extend(parsed)
        summary["secure_trace"] = stats.as_dict()
    elif secure_setting is True or isinstance(secure_setting, str):
        raise ValueError(f"missing secure log: {secure_path}")

    merged = []
    for event in (*normal_events, *secure_events):
        attrs = dict(event.attrs)
        attrs.setdefault("source_seq", event.seq)
        merged.append(Event(len(merged) + 1, event.op, event.actor, attrs))
    summary["trace_sources"] = dict(sorted(Counter(
        str(event.get("source", "unspecified")) for event in merged
    ).items()))
    return [RunHistory(
        label, role, group, relative.as_posix(), tuple(merged), summary
    )]


def iter_corpus(
    project: Path, spec_path: Path, *, secure_logs: bool = False,
) -> Iterable[RunHistory]:
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    if not isinstance(spec, Mapping) or not isinstance(spec.get("records"), list):
        raise ValueError("corpus must contain a records list")
    found = False
    for record in spec["records"]:
        if not isinstance(record, Mapping):
            raise ValueError("each corpus record must be an object")
        for run in _load_one(
            project.resolve(), record, secure_logs=secure_logs,
        ):
            found = True
            yield run
    if not found:
        raise ValueError("corpus resolved to no histories")


def load_corpus(
    project: Path, spec_path: Path, *, secure_logs: bool = False,
) -> list[RunHistory]:
    return list(iter_corpus(project, spec_path, secure_logs=secure_logs))


def relation_graph(runs: Sequence[RunHistory], elements: Sequence[Element]) -> dict[str, Any]:
    nodes: dict[str, dict[str, str]] = {}
    edges: set[tuple[str, str, str]] = set()
    for run in runs:
        run_id = f"run:{run.label}"
        nodes[run_id] = {"id": run_id, "kind": "run", "label": run.label}
        for event in run.events:
            principal = f"principal:{_principal(event)}"
            nodes[principal] = {"id": principal, "kind": "principal",
                                "label": _principal(event)}
            edges.add((principal, run_id, "participates-in"))
            if event.get("object") is not None:
                obj = f"object:{event.get('object')}"
                nodes[obj] = {"id": obj, "kind": "object",
                              "label": str(event.get("object"))}
                edges.add((principal, obj, event.op))
    for element in elements:
        element_id = f"element:{element.element_id}"
        nodes[element_id] = {"id": element_id, "kind": "element",
                             "label": element.title}
        for evidence in element.evidence:
            if evidence.get("run") is not None:
                edges.add((element_id, f"run:{evidence['run']}", "supported-by"))
    return {
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": [
            {"source": source, "target": target, "relation": relation}
            for source, target, relation in sorted(edges)
        ],
    }


def build_report(runs: Sequence[RunHistory], elements: Sequence[Element],
                 *, spec: str) -> dict[str, Any]:
    return {
        "schema": "teeweaver-elements-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "meaning": (
            "Elements are evidence-backed dynamic facts or hypotheses for downstream AI. "
            "They are not vulnerability findings and must not be submitted without promotion."
        ),
        "score_meaning": (
            "The 0-100 score prioritizes follow-up experiments using evidence strength, "
            "repetition, and dynamic specificity. It is not CVSS, severity, exploitability, "
            "or bounty likelihood."
        ),
        "spec": spec,
        "corpus_summary": {
            "runs": len(runs),
            "events": sum(len(run.events) for run in runs),
            "roles": dict(sorted(Counter(run.role for run in runs).items())),
            "groups": dict(sorted(Counter(run.group for run in runs).items())),
        },
        "element_counts": dict(sorted(Counter(item.kind for item in elements).items())),
        "elements": [item.as_dict() for item in elements],
        "relation_graph": relation_graph(runs, elements),
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# TEEWeaver dynamic element report", "",
        f"Corpus: {report['corpus_summary']['runs']} runs, "
        f"{report['corpus_summary']['events']} events. "
        "These are experiment-design elements, not vulnerability claims.", "",
    ]
    for item in report["elements"]:
        lines.extend((
            f"## {item['score']}/100 — {item['title']}", "",
            f"- ID: `{item['element_id']}`", f"- Kind: `{item['kind']}`",
            f"- Confidence: **{item['confidence']}**", "",
            str(item["claim"]), "", "Evidence:", "",
        ))
        for evidence in item["evidence"][:8]:
            lines.append(f"- `{json.dumps(evidence, sort_keys=True)}`")
        lines.extend(("", "Why this needs dynamic evidence:", "", str(item["why_dynamic"]),
                      "", "Next experiments:", ""))
        for experiment in item["next_experiments"]:
            lines.append(f"- {experiment}")
        lines.extend(("", "Caveats / falsification:", ""))
        for caveat in [*item["caveats"], *item["falsifiers"]]:
            lines.append(f"- {caveat}")
        lines.append("")
    return "\n".join(lines) + "\n"
