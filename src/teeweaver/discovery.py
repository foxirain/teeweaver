from __future__ import annotations

import hashlib
import json
import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from itertools import combinations
from typing import Any, Iterable, Mapping, Sequence

from .elements import Element, RunHistory
from .events import Event


CONTROL_ROLES = frozenset({"baseline", "clean", "clean-control", "control"})
RELATIONAL_FAMILIES = frozenset({
    "byte-continuity",
    "call-completion",
    "cross-principal",
    "epoch-continuity",
    "failure-followup",
    "identity-alias",
    "identity-binding",
    "incomplete-transition",
    "lifecycle",
    "mapping-alias",
    "order",
    "overlap",
    "principal-handoff",
    "progress-cycle",
    "refcount-transition",
    "resurrection-transition",
    "reentrancy",
    "reset-epoch",
    "retry-transition",
    "state-alias",
    "store-fallback",
    "terminal-followup",
    "value-transition",
    "wait-transition",
})
TEMPORAL_FAMILIES = frozenset({
    "failure-followup",
    "call-completion",
    "incomplete-transition",
    "lifecycle",
    "order",
    "overlap",
    "principal-handoff",
    "progress-cycle",
    "refcount-transition",
    "resurrection-transition",
    "reentrancy",
    "reset-epoch",
    "retry-transition",
    "store-fallback",
    "terminal-followup",
    "wait-transition",
})
FAMILY_WEIGHTS = {
    "cardinality": 0.2,
    "operation": 0.5,
    "outcome": 0.75,
    "semantic-state": 0.15,
    "byte-continuity": 3.0,
    "call-completion": 2.5,
    "cross-principal": 2.5,
    "epoch-continuity": 3.0,
    "failure-followup": 3.0,
    "identity-alias": 2.5,
    "identity-binding": 3.0,
    "incomplete-transition": 3.0,
    "lifecycle": 1.5,
    "mapping-alias": 3.0,
    "order": 1.25,
    "overlap": 2.5,
    "principal-handoff": 2.75,
    "progress-cycle": 1.5,
    "refcount-transition": 3.0,
    "resurrection-transition": 3.25,
    "reentrancy": 3.0,
    "reset-epoch": 2.5,
    "retry-transition": 2.75,
    "state-alias": 2.0,
    "store-fallback": 3.0,
    "terminal-followup": 3.0,
    "value-transition": 2.5,
    "wait-transition": 2.75,
}

RESOURCE_FIELDS = (
    "object", "session", "operation", "request", "call", "key", "thread",
    "context", "endpoint",
)


def _stable_id(prefix: str, value: str) -> str:
    suffix = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{suffix}"


def _principal(event: Event) -> str:
    return str(event.get("process", event.actor))


def _order_domain(event: Event) -> str:
    """Return the stream in which relative event order is trustworthy."""

    return str(event.get("order_domain", "default"))


def _events_by_order_domain(events: Sequence[Event]) -> dict[str, list[Event]]:
    domains: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        domains[_order_domain(event)].append(event)
    return domains


def _action(event: Event) -> str:
    for key in ("action", "func", "kind", "command"):
        value = event.get(key)
        if value is not None:
            return f"{event.op}[{key}={value}]"
    return event.op


def _event_ref(run: RunHistory, event: Event) -> dict[str, Any]:
    value: dict[str, Any] = {
        "run": run.label,
        "seq": event.seq,
        "op": event.op,
        "actor": event.actor,
    }
    for key in (
        "process", "object", "generation", "receiver", "target", "action",
        "func", "kind", "call", "epoch", "ioctl_result", "ioctl_errno",
        "session", "operation", "request", "claims_request", "key", "digest",
        "verified_digest", "consumed_digest", "owner", "thread", "context",
        "endpoint", "source", "order_domain", "source_line", "store", "address", "physical",
        "refcount_local", "refcount_global", "result", "stage", "trace_rule",
        "trace_confidence", "target_thread", "panic_code",
    ):
        if event.get(key) is not None:
            value[key] = event.get(key)
    return value


def _bucket(value: int) -> str:
    if value <= 0:
        return "0"
    if value <= 4:
        return str(value)
    if value <= 8:
        return "5-8"
    if value <= 16:
        return "9-16"
    if value <= 32:
        return "17-32"
    return "33+"


@dataclass(frozen=True, slots=True)
class FeatureObservation:
    """One identity-independent dynamic relationship observed in a run."""

    feature_id: str
    family: str
    key: str
    label: str
    evidence: tuple[Mapping[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["evidence"] = [dict(item) for item in self.evidence]
        return value


@dataclass(frozen=True, slots=True)
class RunProfile:
    label: str
    role: str
    group: str
    path: str
    feature_ids: tuple[str, ...]
    feature_families: Mapping[str, str]
    family_counts: Mapping[str, int]
    quality: Mapping[str, Any]
    surface: Mapping[str, Any]
    outcome: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "role": self.role,
            "group": self.group,
            "path": self.path,
            "feature_ids": list(self.feature_ids),
            "feature_families": dict(self.feature_families),
            "family_counts": dict(self.family_counts),
            "quality": dict(self.quality),
            "surface": dict(self.surface),
            "outcome": self.outcome,
        }


@dataclass(frozen=True, slots=True)
class QueueEntry:
    rank: int
    run: str
    priority_score: float
    marginal_features: tuple[str, ...]
    control_unseen_features: tuple[str, ...]
    rare_features: tuple[str, ...]
    relational_families: tuple[str, ...]
    nearest_run: str | None
    nearest_similarity: float | None
    contrast_run: str | None
    contrast_kind: str | None
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class _Collector:
    def __init__(self) -> None:
        self._values: dict[tuple[str, str], dict[str, Any]] = {}

    def add(
        self,
        family: str,
        key: str,
        label: str,
        *evidence: Mapping[str, Any],
    ) -> None:
        slot = self._values.setdefault(
            (family, key), {"label": label, "evidence": [], "evidence_keys": set()}
        )
        if len(slot["evidence"]) >= 6:
            return
        known = slot["evidence_keys"]
        for item in evidence:
            encoded = json.dumps(
                item, sort_keys=True, separators=(",", ":"), default=str
            )
            if encoded not in known and len(slot["evidence"]) < 6:
                slot["evidence"].append(dict(item))
                known.add(encoded)

    def finish(self) -> tuple[FeatureObservation, ...]:
        observations = []
        for (family, key), value in sorted(self._values.items()):
            identity = json.dumps([family, key], separators=(",", ":"))
            observations.append(FeatureObservation(
                feature_id=_stable_id("feature", identity),
                family=family,
                key=key,
                label=str(value["label"]),
                evidence=tuple(value["evidence"]),
            ))
        return tuple(observations)


def _integer(value: Any) -> int:
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _failed(event: Event) -> bool:
    result = event.get("ioctl_result")
    explicit = event.get("result")
    return event.op.endswith(("_fail", "_error")) or (
        result is not None and _integer(result) < 0
    ) or (explicit is not None and _integer(explicit) != 0)


def _explicit_result(event: Event) -> str | None:
    """Return only an explicitly observable success/failure classification."""

    result = event.get("ioctl_result")
    if result is not None:
        return "failure" if _integer(result) < 0 else "success"
    explicit = event.get("result")
    if explicit is not None:
        return "failure" if _integer(explicit) != 0 else "success"
    if event.op.endswith(("_fail", "_error")):
        return "failure"
    return None


def _normalized_principal_path(events: Sequence[Event]) -> tuple[str, ...]:
    symbols: dict[str, str] = {}
    path = []
    for event in events:
        principal = _principal(event)
        symbol = symbols.setdefault(principal, f"p{len(symbols)}")
        path.append(f"{_action(event)}@{symbol}")
    return tuple(path)


def _quality(run: RunHistory) -> dict[str, Any]:
    issues = {
        (_order_domain(event), str(event.get("call"))): event
        for event in run.events
        if event.op.endswith("_issue") and event.get("call") is not None
    }
    completions = {
        (_order_domain(event), str(event.get("call")))
        for event in run.events
        if event.get("call") is not None and not event.op.endswith("_issue")
    }
    unmatched = sorted(set(issues) - completions)
    timestamped = sum(event.get("time_ns") is not None for event in run.events)
    error = run.summary.get("run_error")
    if unmatched and error and "timeout" in str(error).lower():
        observation = "bounded-incomplete"
    elif unmatched:
        observation = "trace-incomplete"
    elif error:
        observation = "runner-error"
    else:
        observation = "complete"
    warnings = []
    if not run.events:
        warnings.append("empty-trace")
    if unmatched:
        warnings.append("unmatched-call-issues")
    if run.events and timestamped not in {0, len(run.events)}:
        warnings.append("partial-timestamps")
    if not run.summary:
        warnings.append("missing-summary")
    return {
        "observation": observation,
        "events": len(run.events),
        "call_issues": len(issues),
        "unmatched_call_issues": len(unmatched),
        "unmatched_calls": [
            {"order_domain": domain, "call": call}
            for domain, call in unmatched[:16]
        ],
        "timestamp_coverage": round(timestamped / max(1, len(run.events)), 4),
        "warnings": warnings,
    }


def observe_run(run: RunHistory) -> tuple[FeatureObservation, ...]:
    """Extract generic dynamic features without assigning vulnerability meaning."""

    out = _Collector()
    actors = {event.actor for event in run.events}
    principals = {_principal(event) for event in run.events}
    objects = {str(event.get("object")) for event in run.events
               if event.get("object") is not None}
    endpoints = {
        str(event.get("receiver", event.get("target")))
        for event in run.events
        if event.get("receiver", event.get("target")) is not None
    }
    sources = {str(event.get("source", "unspecified")) for event in run.events}
    order_domains = {_order_domain(event) for event in run.events}
    for name, values in (
        ("actors", actors), ("principals", principals),
        ("objects", objects), ("endpoints", endpoints),
        ("sources", sources), ("order-domains", order_domains),
    ):
        out.add(
            "cardinality", f"{name}:{_bucket(len(values))}",
            f"{name} cardinality is {_bucket(len(values))}",
            {"run": run.label, "dimension": name, "count": len(values)},
        )

    for event in run.events:
        action = _action(event)
        out.add("operation", action, f"Observed {action}", _event_ref(run, event))

    # State identifiers are already semantic hashes. Keep a deterministic
    # bottom-k sketch so long executions do not make the AI bundle enormous
    # or drown relationship features in thousands of one-off states.
    sampled_states = sorted(
        run.states,
        key=lambda state: hashlib.sha256(state.encode("utf-8")).hexdigest(),
    )[:512]
    out.add(
        "cardinality", f"semantic-states:{_bucket(len(run.states))}",
        f"Semantic-state cardinality is {_bucket(len(run.states))}",
        {"run": run.label, "count": len(run.states), "sampled": len(sampled_states)},
    )
    for state in sampled_states:
        out.add(
            "semantic-state", f"state:{state}", "Observed semantic state",
            {"run": run.label, "state": state},
        )

    by_object: dict[str, list[Event]] = defaultdict(list)
    by_object_domain: dict[tuple[str, str], list[Event]] = defaultdict(list)
    by_resource: dict[tuple[str, str], list[Event]] = defaultdict(list)
    by_resource_domain: dict[tuple[str, str, str], list[Event]] = defaultdict(list)
    for event in run.events:
        domain = _order_domain(event)
        if event.get("object") is not None:
            obj = str(event.get("object"))
            by_object[obj].append(event)
            by_object_domain[(domain, obj)].append(event)
        for field in RESOURCE_FIELDS:
            if event.get(field) is not None:
                value = str(event.get(field))
                by_resource[(field, value)].append(event)
                by_resource_domain[(domain, field, value)].append(event)
    for (domain, obj), events in sorted(by_object_domain.items()):
        lifecycle = ">".join(_action(event) for event in events[:12])
        out.add(
            "lifecycle", f"domain:{domain}:ops:{lifecycle}",
            f"Observed object lifecycle {lifecycle}",
            *(_event_ref(run, event) for event in events[:4]),
        )
        generations = sorted({str(event.get("generation")) for event in events
                              if event.get("generation") is not None})
        if len(generations) > 1:
            out.add(
                "lifecycle", f"domain:{domain}:generation-span:{len(generations)}",
                f"One raw identity spans {len(generations)} observed generations",
                *(_event_ref(run, event) for event in events[:4]),
            )
    for obj, events in sorted(by_object.items()):
        object_principals = {_principal(event) for event in events}
        if len(object_principals) > 1:
            ops = "|".join(sorted({_action(event) for event in events[:8]}))
            out.add(
                "cross-principal", f"shared-object-actions:{ops}",
                "One object identity is observed across multiple principals",
                *(_event_ref(run, event) for event in events[:6]),
            )

    for (domain, field, value), events in sorted(by_resource_domain.items()):
        lifecycle = ">".join(_action(event) for event in events[:12])
        if field != "object":
            out.add(
                "lifecycle", f"domain:{domain}:resource:{field}:ops:{lifecycle}",
                f"Observed {field} resource lifecycle {lifecycle}",
                *(_event_ref(run, event) for event in events[:4]),
            )
    for (field, value), events in sorted(by_resource.items()):
        resource_principals = {_principal(event) for event in events}
        if len(resource_principals) > 1:
            actions = "|".join(sorted({_action(event) for event in events[:12]}))
            out.add(
                "cross-principal", f"shared-{field}-actions:{actions}",
                f"One {field} identity is observed across multiple principals",
                *(_event_ref(run, event) for event in events[:6]),
            )
        for domain, domain_events in _events_by_order_domain(events).items():
            if len({_principal(event) for event in domain_events}) < 2:
                continue
            path = _normalized_principal_path(domain_events[:12])
            out.add(
                "principal-handoff", f"{domain}:{field}:" + ">".join(path),
                f"Observed ordered {field} handoff " + ">".join(path),
                *(_event_ref(run, event) for event in domain_events[:6]),
            )

    # Runtime identity topology is valuable even when each field is locally
    # well-typed: two protocol namespaces can unexpectedly alias only in an
    # actual execution.  Record field relationships, never the raw identity.
    for event in run.events:
        present = [
            (field, str(event.get(field))) for field in RESOURCE_FIELDS
            if event.get(field) is not None
        ]
        for (left_field, left), (right_field, right) in combinations(present, 2):
            if left != right:
                continue
            fields = sorted((left_field, right_field))
            out.add(
                "identity-alias",
                f"{_action(event)}:{fields[0]}={fields[1]}",
                f"{_action(event)} uses one runtime identity as both "
                f"{fields[0]} and {fields[1]}",
                _event_ref(run, event),
            )

    for event in run.events:
        request = event.get("request")
        claims_request = event.get("claims_request")
        if request is not None and claims_request is not None:
            relation = "same" if str(request) == str(claims_request) else "different"
            out.add(
                "identity-binding",
                f"request-claim:{event.op}:{relation}",
                f"{event.op} binds request and claimed-request identities ({relation})",
                _event_ref(run, event),
            )
        owner = event.get("owner")
        receiver = event.get("receiver")
        if owner is not None and receiver is not None:
            relation = "same" if str(owner) == str(receiver) else "different"
            out.add(
                "identity-binding", f"owner-receiver:{event.op}:{relation}",
                f"{event.op} links owner and receiver identities ({relation})",
                _event_ref(run, event),
            )

    # Refcounts expose ownership and lifetime coupling that is not reconstructable
    # from API return values. Preserve only transition shapes, not raw identities.
    for (domain, obj), events in sorted(by_object_domain.items()):
        samples = [
            event for event in events
            if event.get("refcount_local") is not None
            and event.get("refcount_global") is not None
        ]
        for before, after in zip(samples, samples[1:]):
            before_pair = (
                int(before.get("refcount_local")),
                int(before.get("refcount_global")),
            )
            after_pair = (
                int(after.get("refcount_local")),
                int(after.get("refcount_global")),
            )
            transition = (
                f"{_bucket(before_pair[0])}:{_bucket(before_pair[1])}>"
                f"{_bucket(after_pair[0])}:{_bucket(after_pair[1])}"
            )
            out.add(
                "refcount-transition", f"domain:{domain}:{transition}",
                f"Observed local:global refcount transition {transition}",
                _event_ref(run, before), _event_ref(run, after),
            )

    attempts_by_call: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in run.events:
        if (event.op.startswith("secure_binary_lookup_complete")
                and event.get("store") is not None
                and event.get("call") is not None):
            attempts_by_call[
                (_order_domain(event), str(event.get("call")))
            ].append(event)
    for (domain, call), attempts in sorted(attempts_by_call.items()):
        if len(attempts) < 2:
            continue
        path = ">".join(
            f"{event.get('store')}:{_explicit_result(event) or 'unknown'}"
            for event in attempts[:8]
        )
        out.add(
            "store-fallback", f"domain:{domain}:{path}",
            f"One binary-load attempt traverses stores as {path}",
            *(_event_ref(run, event) for event in attempts[:6]),
        )

    # Make opaque issue/completion paths explicit. This is deliberately
    # independent of API names so native secure-log pairs and Normal-World
    # instrumentation share one representation.
    for (domain, field, value), events in sorted(by_resource_domain.items()):
        if field != "call":
            continue
        for index, issue in enumerate(events):
            if not issue.op.endswith("_issue"):
                continue
            completion = next(
                (
                    later for later in events[index + 1:]
                    if not later.op.endswith("_issue")
                ),
                None,
            )
            if completion is None:
                continue
            relation = (
                "same-principal" if _principal(issue) == _principal(completion)
                else "cross-principal"
            )
            path = f"{_action(issue)}>{_action(completion)}:{relation}"
            out.add(
                "call-completion", f"domain:{domain}:{path}",
                f"Observed call completion path {path}",
                _event_ref(run, issue), _event_ref(run, completion),
            )

    terminal_ops = {
        "ffa_reclaim", "operation_cancel", "secure_rpc_free",
        "secure_session_destroy_complete", "secure_ta_context_destroy",
        "shm_release",
    }
    for (domain, field, value), events in sorted(by_resource_domain.items()):
        if field in {"call", "thread"}:
            continue
        for index, terminal in enumerate(events[:-1]):
            if terminal.op not in terminal_ops:
                continue
            later = events[index + 1]
            relation = (
                "terminal-repeat" if later.op in terminal_ops
                else "post-terminal-observation"
            )
            path = f"{_action(terminal)}>{_action(later)}:{relation}"
            out.add(
                "terminal-followup", f"domain:{domain}:{field}:{path}",
                f"A {field} identity is observed after terminal action: {path}",
                _event_ref(run, terminal), _event_ref(run, later),
            )

    for (domain, obj), events in sorted(by_object_domain.items()):
        for index, resurrect in enumerate(events):
            if resurrect.op != "secure_ffa_resurrect":
                continue
            before = next((
                event for event in reversed(events[:index])
                if event.get("refcount_local") is not None
                and event.get("refcount_global") is not None
            ), None)
            after = next((
                event for event in events[index + 1:]
                if event.get("refcount_local") is not None
                and event.get("refcount_global") is not None
            ), None)

            def counts(event: Event | None) -> str:
                if event is None:
                    return "unobserved"
                return (
                    f"{_bucket(int(event.get('refcount_local')))}:"
                    f"{_bucket(int(event.get('refcount_global')))}"
                )

            shape = f"{counts(before)}>resurrect>{counts(after)}"
            evidence = [event for event in (before, resurrect, after)
                        if event is not None]
            out.add(
                "resurrection-transition", f"domain:{domain}:{shape}",
                f"Observed FF-A resurrection with refcount shape {shape}",
                *(_event_ref(run, event) for event in evidence),
            )

    wait_groups: dict[tuple[str, str, str], list[Event]] = defaultdict(list)
    for event in run.events:
        if event.op not in {"secure_thread_sleep", "secure_thread_wake"}:
            continue
        wait_groups[(
            _order_domain(event), str(event.get("object")),
            str(event.get("target_thread")),
        )].append(event)
    for (domain, wait_object, target_thread), events in sorted(wait_groups.items()):
        sleepers: list[Event] = []
        for event in events:
            if event.op == "secure_thread_sleep":
                sleepers.append(event)
                continue
            if not sleepers:
                out.add(
                    "wait-transition", f"domain:{domain}:wake-without-sleep",
                    "A wake is observed without a preceding sleep in this log",
                    _event_ref(run, event),
                )
                continue
            sleep = sleepers.pop(0)
            relation = (
                "same-executor" if sleep.actor == event.actor
                else "cross-executor"
            )
            out.add(
                "wait-transition", f"domain:{domain}:sleep>wake:{relation}",
                f"Observed secure-thread sleep/wake handoff ({relation})",
                *(
                    _event_ref(run, item)
                    for item in (sleep, event)
                ),
            )
        if sleepers:
            out.add(
                "wait-transition",
                f"domain:{domain}:outstanding-sleep:{_bucket(len(sleepers))}",
                f"Log ends with {_bucket(len(sleepers))} unmatched sleep observations",
                *(_event_ref(run, event) for event in sleepers[-4:]),
            )

    by_address: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in run.events:
        if event.get("address") is not None:
            by_address[(_order_domain(event), str(event.get("address")))].append(event)
    for (domain, address), events in sorted(by_address.items()):
        actions = sorted({_action(event) for event in events})
        identities = {
            str(event.get("object")) for event in events
            if event.get("object") is not None
        }
        if len(actions) < 2 and len(identities) < 2:
            continue
        shape = "|".join(actions[:8])
        out.add(
            "mapping-alias", f"domain:{domain}:actions:{shape}",
            "One virtual address participates in multiple observed mapping roles",
            *(_event_ref(run, event) for event in events[:6]),
        )

    verified: dict[tuple[str, str], Event] = {}
    for event in run.events:
        if event.op == "object_verify" and event.get("object") is not None:
            verified[(_order_domain(event), str(event.get("object")))] = event
        elif event.op == "object_consume" and event.get("object") is not None:
            key = (_order_domain(event), str(event.get("object")))
            if key not in verified:
                continue
            before = verified[key]
            before_digest = before.get("digest", before.get("verified_digest"))
            after_digest = event.get("digest", event.get("consumed_digest"))
            relation = "unknown"
            if before_digest is not None and after_digest is not None:
                relation = "same" if str(before_digest) == str(after_digest) else "different"
            out.add(
                "byte-continuity", f"verify-consume:{relation}",
                f"Verified and consumed bytes have {relation} digests",
                _event_ref(run, before), _event_ref(run, event),
            )

    storage_acks: dict[tuple[str, str], Event] = {}
    for event in run.events:
        if event.op == "storage_ack" and event.get("key") is not None:
            storage_acks[(_order_domain(event), str(event.get("key")))] = event
        elif event.op == "storage_observe" and event.get("key") is not None:
            key = (_order_domain(event), str(event.get("key")))
            if key not in storage_acks:
                continue
            before = storage_acks[key]
            before_digest = before.get("digest")
            after_digest = event.get("digest")
            relation = "unknown"
            if before_digest is not None and after_digest is not None:
                relation = "same" if str(before_digest) == str(after_digest) else "different"
            out.add(
                "value-transition", f"storage-ack-observe:{relation}",
                f"Acknowledged and observed storage values are {relation}",
                _event_ref(run, before), _event_ref(run, event),
            )

    ordered_domains = _events_by_order_domain(run.events)
    for domain, domain_events in sorted(ordered_domains.items()):
        interesting = [
            event for event in domain_events if event.op != "trace_metadata"
        ]
        for index, first in enumerate(interesting):
            for second in interesting[index + 1:index + 9]:
                if _principal(first) == _principal(second):
                    continue
                left, right = _action(first), _action(second)
                if left == right:
                    continue
                out.add(
                    "order", f"domain:{domain}:cross-principal:{left}>{right}",
                    f"Cross-principal order {left} then {right}",
                    _event_ref(run, first), _event_ref(run, second),
                )

        # Repeated short motifs with no intervening action are compact evidence
        # of retry loops, polling, or progress stalls within one ordered stream.
        actions = [_action(event) for event in interesting]
        for width in range(1, min(4, len(actions) // 3) + 1):
            index = 0
            while index + width * 3 <= len(actions):
                motif = actions[index:index + width]
                repeats = 1
                while (index + (repeats + 1) * width <= len(actions)
                       and actions[index + repeats * width:
                                   index + (repeats + 1) * width] == motif):
                    repeats += 1
                if repeats >= 3:
                    key = "|".join(motif)
                    evidence_events = interesting[
                        index:index + min(width * repeats, 6)
                    ]
                    out.add(
                        "progress-cycle",
                        f"domain:{domain}:motif:{key}:repeats:{_bucket(repeats)}",
                        f"Observed contiguous action motif {key} repeat "
                        f"{_bucket(repeats)} times",
                        *(_event_ref(run, event) for event in evidence_events),
                    )
                    index += width * repeats
                else:
                    index += 1

    # A single action can move between explicit failure and success only at
    # runtime.  Preserve the transition shape while ignoring raw identities.
    results_by_action: dict[tuple[str, str], list[tuple[str, Event]]] = defaultdict(list)
    for event in run.events:
        result = _explicit_result(event)
        if result is not None:
            results_by_action[(_order_domain(event), _action(event))].append(
                (result, event)
            )
    for (domain, action), results in sorted(results_by_action.items()):
        classes = {result for result, _ in results}
        if len(classes) < 2:
            continue
        transition = ">".join(result for result, _ in results[:8])
        out.add(
            "retry-transition", f"domain:{domain}:{action}:{transition}",
            f"{action} changes explicit result across retries: {transition}",
            *(_event_ref(run, event) for _, event in results[:6]),
        )

    cleanup_ops = {"reset", "ffa_relinquish", "ffa_reclaim", "shm_release",
                   "session_close", "operation_cancel"}
    for domain, domain_events in sorted(ordered_domains.items()):
        for index, failed in enumerate(domain_events):
            if not _failed(failed):
                continue
            obj = failed.get("object")
            endpoint = failed.get("receiver", failed.get("target"))
            for later in domain_events[index + 1:index + 65]:
                if later.op in cleanup_ops and (
                    obj is None or later.get("object") in {None, obj}
                ):
                    break
                related = obj is not None and later.get("object") == obj
                if not related and endpoint is not None:
                    related = endpoint == later.get("receiver", later.get("target"))
                if related:
                    out.add(
                        "failure-followup",
                        f"domain:{domain}:{_action(failed)}>{_action(later)}",
                        f"Failed {_action(failed)} is followed by related "
                        f"{_action(later)}",
                        _event_ref(run, failed), _event_ref(run, later),
                    )
                    break

    issues = {
        (_order_domain(event), str(event.get("call"))): event
        for event in run.events
        if event.op.endswith("_issue") and event.get("call") is not None
    }
    completions = {
        (_order_domain(event), str(event.get("call")))
        for event in run.events
        if event.get("call") is not None and not event.op.endswith("_issue")
    }
    for domain, call in sorted(set(issues) - completions):
        issue = issues[(domain, call)]
        out.add(
            "incomplete-transition", f"domain:{domain}:unmatched:{_action(issue)}",
            f"Issued {_action(issue)} has no observed completion",
            _event_ref(run, issue),
        )

    active: dict[tuple[str, str], Event] = {}
    for event in run.events:
        call = event.get("call")
        if call is None:
            continue
        domain = _order_domain(event)
        call_id = (domain, str(call))
        if event.op.endswith("_issue"):
            for (other_domain, _), other in active.items():
                if other_domain != domain:
                    continue
                pair = sorted((_action(other), _action(event)))
                if _principal(other) == _principal(event):
                    out.add(
                        "reentrancy", f"nested:{pair[0]}|{pair[1]}",
                        f"One principal has nested in-flight calls: "
                        f"{pair[0]} and {pair[1]}",
                        _event_ref(run, other), _event_ref(run, event),
                    )
                else:
                    out.add(
                        "overlap", f"concurrent:{pair[0]}|{pair[1]}",
                        f"Concurrent in-flight calls: {pair[0]} and {pair[1]}",
                        _event_ref(run, other), _event_ref(run, event),
                    )
            active[call_id] = event
        else:
            active.pop(call_id, None)

    for domain, domain_events in sorted(ordered_domains.items()):
        reset_indexes = [
            index for index, event in enumerate(domain_events)
            if event.op == "reset"
        ]
        for index in reset_indexes:
            before = {
                _action(event)
                for event in domain_events[max(0, index - 8):index]
            }
            after = {
                _action(event) for event in domain_events[index + 1:index + 9]
            }
            for left in sorted(before):
                for right in sorted(after):
                    out.add(
                        "reset-epoch", f"domain:{domain}:{left}>reset>{right}",
                        f"Reset separates {left} from {right}",
                        _event_ref(run, domain_events[index]),
                    )
            before_events = domain_events[max(0, index - 64):index]
            after_events = domain_events[index + 1:index + 65]
            for field in RESOURCE_FIELDS:
                before_by_value = {
                    str(event.get(field)): event for event in before_events
                    if event.get(field) is not None
                }
                after_by_value = {
                    str(event.get(field)): event for event in after_events
                    if event.get(field) is not None
                }
                for value in sorted(set(before_by_value) & set(after_by_value))[:4]:
                    out.add(
                        "epoch-continuity",
                        f"domain:{domain}:identity-survives-reset:{field}",
                        f"One {field} identity is observed on both sides of reset",
                        _event_ref(run, before_by_value[value]),
                        _event_ref(run, domain_events[index]),
                        _event_ref(run, after_by_value[value]),
                    )

    statuses = run.summary.get("statuses", {})
    for name, value in sorted(statuses.items()):
        out.add(
            "outcome", f"status:{name}={value}",
            f"Workload status {name}={value}",
            {"run": run.label, "status": str(name), "value": str(value)},
        )
    error = run.summary.get("run_error")
    if error:
        error_kind = str(error).split(":", 1)[0]
        out.add(
            "outcome", f"run-error:{error_kind}",
            f"Runner recorded {error_kind}",
            {"run": run.label, "run_error": str(error)},
        )
    return out.finish()


def _surface(run: RunHistory) -> dict[str, Any]:
    actions = Counter(_action(event) for event in run.events)
    actors = sorted({event.actor for event in run.events})
    principals = sorted({_principal(event) for event in run.events})
    endpoints = sorted({
        str(event.get("receiver", event.get("target")))
        for event in run.events
        if event.get("receiver", event.get("target")) is not None
    })
    mutable_fields = sorted({
        field
        for event in run.events
        for field in ("object", "generation", "receiver", "target", "action", "func")
        if event.get(field) is not None
    })
    interventions = {"repeat", "delay"} if actions else set()
    if len(principals) > 1:
        interventions.add("schedule-order")
    if {"object", "receiver", "target"} & set(mutable_fields):
        interventions.add("identity-substitution")
    if any(event.op == "reset" for event in run.events):
        interventions.add("reset-replay")
    if any(event.op.startswith("storage_") for event in run.events):
        interventions.add("persistence-cut")
    return {
        "actors": actors,
        "principals": principals,
        "endpoints": endpoints,
        "sources": sorted({
            str(event.get("source", "unspecified")) for event in run.events
        }),
        "order_domains": sorted({_order_domain(event) for event in run.events}),
        "actions": [
            {"action": action, "occurrences": count}
            for action, count in sorted(actions.items())
        ],
        "mutable_fields": mutable_fields,
        "supported_interventions": sorted(interventions),
    }


def profile_runs(
    runs: Sequence[RunHistory],
) -> tuple[list[RunProfile], dict[str, FeatureObservation]]:
    profiles: list[RunProfile] = []
    catalog: dict[str, FeatureObservation] = {}
    for run in runs:
        observations = observe_run(run)
        for item in observations:
            previous = catalog.get(item.feature_id)
            if previous is None:
                catalog[item.feature_id] = item
                continue
            evidence = list(previous.evidence)
            encoded = {
                json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
                for value in evidence
            }
            for value in item.evidence:
                marker = json.dumps(
                    value, sort_keys=True, separators=(",", ":"), default=str
                )
                if marker not in encoded and len(evidence) < 8:
                    evidence.append(value)
                    encoded.add(marker)
            catalog[item.feature_id] = FeatureObservation(
                item.feature_id, item.family, item.key, item.label, tuple(evidence)
            )
        family_counts = Counter(item.family for item in observations)
        profiles.append(RunProfile(
            label=run.label,
            role=run.role,
            group=run.group,
            path=run.path,
            feature_ids=tuple(item.feature_id for item in observations),
            feature_families={
                item.feature_id: item.family for item in observations
            },
            family_counts=dict(sorted(family_counts.items())),
            quality=_quality(run),
            surface=_surface(run),
            outcome=repr(run.outcome),
        ))
    return profiles, catalog


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def _behavior_features(
    profile: RunProfile, *, exclude: frozenset[str] = frozenset({"outcome"}),
) -> set[str]:
    """Select runtime-history features without leaking visible outcomes."""

    return {
        feature for feature in profile.feature_ids
        if profile.feature_families.get(feature) not in exclude
    }


def _nearest(
    target: RunProfile, profiles: Sequence[RunProfile],
) -> tuple[str | None, float | None]:
    target_features = _behavior_features(target)
    peers = [profile for profile in profiles if profile.label != target.label]
    if not peers:
        return None, None
    peer = max(
        peers,
        key=lambda item: (
            _jaccard(target_features, _behavior_features(item)), item.label
        ),
    )
    return peer.label, round(
        _jaccard(target_features, _behavior_features(peer)), 4
    )


def _contrast(
    target: RunProfile, profiles: Sequence[RunProfile],
) -> tuple[str | None, str | None]:
    peers = [profile for profile in profiles
             if profile.label != target.label and profile.group == target.group]
    if not peers:
        return None, None
    different_outcome = [peer for peer in peers if peer.outcome != target.outcome]
    if different_outcome:
        peer = max(
            different_outcome,
            key=lambda item: (
                -len(_behavior_features(target) ^ _behavior_features(item)),
                item.label,
            ),
        )
        target_history = _behavior_features(target)
        peer_history = _behavior_features(peer)
        core_exclusions = frozenset({"outcome"}) | TEMPORAL_FAMILIES
        target_core = _behavior_features(target, exclude=core_exclusions)
        peer_core = _behavior_features(peer, exclude=core_exclusions)
        if target_history == peer_history:
            kind = "same-history-different-outcome"
        elif target_core == peer_core:
            kind = "same-core-different-schedule-outcome"
        else:
            kind = "same-group-different-outcome"
        return peer.label, kind
    same_outcome = [peer for peer in peers
                    if _behavior_features(peer) != _behavior_features(target)]
    if same_outcome:
        peer = max(
            same_outcome,
            key=lambda item: len(
                _behavior_features(target) ^ _behavior_features(item)
            ),
        )
        core_exclusions = frozenset({"outcome"}) | TEMPORAL_FAMILIES
        target_core = _behavior_features(target, exclude=core_exclusions)
        peer_core = _behavior_features(peer, exclude=core_exclusions)
        kind = (
            "same-outcome-different-schedule"
            if target_core == peer_core else "same-outcome-different-history"
        )
        return peer.label, kind
    return None, None


def rank_novelty(
    profiles: Sequence[RunProfile], *, budget: int | None = None,
) -> list[QueueEntry]:
    """Greedily select runs that maximize rare, control-unseen semantic relations."""

    if budget is not None and budget < 1:
        raise ValueError("budget must be positive")
    frequencies = Counter(
        feature for profile in profiles for feature in set(profile.feature_ids)
    )
    controls = {
        feature for profile in profiles if profile.role.lower() in CONTROL_ROLES
        for feature in profile.feature_ids
    }
    has_controls = any(
        profile.role.lower() in CONTROL_ROLES for profile in profiles
    )
    selected: list[QueueEntry] = []
    covered: set[str] = set(controls)
    candidates = [
        profile for profile in profiles
        if profile.role.lower() not in CONTROL_ROLES
    ]
    if not candidates:
        candidates = list(profiles)
        covered = set()
    remaining = {profile.label: profile for profile in candidates}
    maximum = min(len(candidates), budget if budget is not None else len(candidates))
    while remaining and len(selected) < maximum:
        scored: list[tuple[float, str, RunProfile, dict[str, Any]]] = []
        for profile in remaining.values():
            features = set(profile.feature_ids)
            marginal = features - covered
            unseen = features - controls if has_controls else set()
            rare = {feature for feature in features if frequencies[feature] <= 2}
            families = {
                family for feature in features
                for family in (profile.feature_families.get(feature),)
                if family in RELATIONAL_FAMILIES
            }
            def weight(feature: str) -> float:
                family = profile.feature_families.get(feature, "unknown")
                return FAMILY_WEIGHTS.get(family, 1.0)

            marginal_weight = sum(weight(feature) for feature in marginal)
            unseen_weight = sum(weight(feature) for feature in unseen)
            rare_weight = sum(weight(feature) for feature in rare)
            rarity = sum(
                weight(feature) / frequencies[feature] for feature in features
            )
            score = (
                marginal_weight * 3.0
                + unseen_weight * 1.5
                + rare_weight * 0.75
                + len(families) * 4.0
                + rarity
            )
            observation = str(profile.quality.get("observation"))
            if observation == "runner-error" and not families:
                score *= 0.25
            elif observation in {"bounded-incomplete", "trace-incomplete"}:
                score += 3.0
            contrast_run, contrast_kind = _contrast(profile, profiles)
            if contrast_run:
                score += 5.0
            scored.append((score, profile.label, profile, {
                "marginal": marginal,
                "unseen": unseen,
                "rare": rare,
                "families": families,
                "contrast_run": contrast_run,
                "contrast_kind": contrast_kind,
            }))
        score, _, profile, detail = max(scored, key=lambda item: (item[0], item[1]))
        nearest_run, nearest_similarity = _nearest(profile, profiles)
        reasons = [f"{len(detail['marginal'])} feature(s) add corpus coverage"]
        if has_controls:
            reasons.append(
                f"{len(detail['unseen'])} feature(s) are absent from controls"
            )
        else:
            reasons.append("corpus has no control-role run; no control bonus applied")
        if detail["families"]:
            reasons.append(
                "relational evidence: " + ", ".join(sorted(detail["families"]))
            )
        if detail["contrast_run"]:
            reasons.append(
                f"contrast {detail['contrast_run']} ({detail['contrast_kind']})"
            )
        selected.append(QueueEntry(
            rank=len(selected) + 1,
            run=profile.label,
            priority_score=round(score, 3),
            marginal_features=tuple(sorted(detail["marginal"])),
            control_unseen_features=tuple(sorted(detail["unseen"])),
            rare_features=tuple(sorted(detail["rare"])),
            relational_families=tuple(sorted(detail["families"])),
            nearest_run=nearest_run,
            nearest_similarity=nearest_similarity,
            contrast_run=detail["contrast_run"],
            contrast_kind=detail["contrast_kind"],
            reasons=tuple(reasons),
        ))
        covered.update(profile.feature_ids)
        del remaining[profile.label]
    return selected


def mine_contrasts(
    profiles: Sequence[RunProfile], *, limit: int = 256,
) -> list[dict[str, Any]]:
    """Find close outcome deltas and hidden-history aliases without fixed bug rules."""

    if limit < 1:
        return []
    candidates: list[tuple[float, str, dict[str, Any]]] = []
    by_group: dict[str, list[RunProfile]] = defaultdict(list)
    for profile in profiles:
        by_group[profile.group].append(profile)
    for group, members in sorted(by_group.items()):
        for left, right in combinations(sorted(members, key=lambda item: item.label), 2):
            if (left.role.lower() in CONTROL_ROLES
                    and right.role.lower() in CONTROL_ROLES):
                continue
            left_features = _behavior_features(left)
            right_features = _behavior_features(right)
            if left_features == right_features and left.outcome == right.outcome:
                continue
            similarity = _jaccard(left_features, right_features)
            core_exclusions = frozenset({"outcome"}) | TEMPORAL_FAMILIES
            left_core = _behavior_features(left, exclude=core_exclusions)
            right_core = _behavior_features(right, exclude=core_exclusions)
            core_similarity = _jaccard(left_core, right_core)
            left_only = left_features - right_features
            right_only = right_features - left_features
            unique = left_only | right_only
            relational_unique = {
                feature for feature in unique
                if left.feature_families.get(
                    feature, right.feature_families.get(feature)
                ) in RELATIONAL_FAMILIES
            }
            if left.outcome != right.outcome and left_features == right_features:
                kind = "same-history-different-outcome"
                score = 100.0
            elif left.outcome != right.outcome and left_core == right_core:
                kind = "same-core-different-schedule-outcome"
                score = 90.0 + min(10, len(relational_unique))
            elif left.outcome == right.outcome and left_core == right_core:
                kind = "same-outcome-different-schedule"
                score = 45.0 + min(10, len(relational_unique))
            elif left.outcome == right.outcome:
                kind = "same-outcome-different-history"
                score = (
                    (1.0 - similarity) * 30.0
                    + min(12, len(relational_unique)) * 3.0
                )
            else:
                kind = "different-outcome-nearby-history"
                score = (
                    similarity * 40.0
                    + min(12, len(relational_unique)) * 3.0
                )
            identity = json.dumps(
                [group, left.label, right.label, kind], separators=(",", ":")
            )
            value = {
                "contrast_id": _stable_id("contrast", identity),
                "group": group,
                "kind": kind,
                "left_run": left.label,
                "right_run": right.label,
                "left_outcome": left.outcome,
                "right_outcome": right.outcome,
                "feature_jaccard": round(similarity, 4),
                "core_feature_jaccard": round(core_similarity, 4),
                "shared_features": len(left_features & right_features),
                "left_only_features": sorted(left_only)[:64],
                "right_only_features": sorted(right_only)[:64],
                "relational_unique_features": sorted(relational_unique)[:64],
                "follow_up_score": round(score, 3),
                "meaning": (
                    "A controlled comparison target; association does not establish "
                    "that the feature delta caused the outcome."
                ),
            }
            candidates.append((score, value["contrast_id"], value))
    return [
        value for _, _, value in sorted(
            candidates, key=lambda item: (-item[0], item[1])
        )[:limit]
    ]


def mine_outcome_associations(
    profiles: Sequence[RunProfile], *, limit: int = 256,
    per_family_limit: int = 32,
) -> list[dict[str, Any]]:
    """Rank feature/outcome co-variation as experiment targets, not causal claims."""

    if len(profiles) < 3 or limit < 1 or per_family_limit < 1:
        return []
    by_group: dict[str, list[RunProfile]] = defaultdict(list)
    for profile in profiles:
        by_group[profile.group].append(profile)
    candidates: list[tuple[float, str, dict[str, Any]]] = []
    for group, members in sorted(by_group.items()):
        if len(members) < 4:
            continue
        all_outcomes = sorted({profile.outcome for profile in members})
        feature_profiles: dict[str, list[RunProfile]] = defaultdict(list)
        for profile in members:
            for feature in set(profile.feature_ids):
                if profile.feature_families.get(feature) == "outcome":
                    continue
                feature_profiles[feature].append(profile)
        for feature, present in feature_profiles.items():
            if len(present) < 2 or len(members) - len(present) < 2:
                continue
            present_labels = {item.label for item in present}
            absent = [
                item for item in members if item.label not in present_labels
            ]
            present_counts = Counter(item.outcome for item in present)
            absent_counts = Counter(item.outcome for item in absent)
            deltas = {
                outcome: abs(
                    present_counts[outcome] / len(present)
                    - absent_counts[outcome] / len(absent)
                )
                for outcome in all_outcomes
            }
            outcome, delta = max(
                deltas.items(), key=lambda item: (item[1], item[0])
            )
            family = next(
                profile.feature_families[feature]
                for profile in present if feature in profile.feature_families
            )
            balance = min(len(present), len(absent))
            score = (
                delta * math.log2(balance + 1)
                * FAMILY_WEIGHTS.get(family, 1.0)
            )
            if score <= 0:
                continue
            value = {
                "group": group,
                "feature_id": feature,
                "family": family,
                "support_count": len(present),
                "absent_count": len(absent),
                "strongest_outcome": outcome,
                "absolute_rate_delta": round(delta, 4),
                "association_score": round(score, 4),
                "present_outcomes": dict(sorted(present_counts.items())),
                "absent_outcomes": dict(sorted(absent_counts.items())),
                "meaning": (
                    "Within-group corpus association only; unobserved inputs "
                    "may explain the delta."
                ),
            }
            candidates.append((score, f"{group}\0{feature}", value))
    selected = []
    family_counts: Counter[str] = Counter()
    for _, _, value in sorted(candidates, key=lambda item: (-item[0], item[1])):
        family = str(value["family"])
        if family_counts[family] >= per_family_limit:
            continue
        selected.append(value)
        family_counts[family] += 1
        if len(selected) >= limit:
            break
    return selected


def mine_feature_cooccurrence(
    profiles: Sequence[RunProfile], *, limit: int = 256,
    per_family_pair_limit: int = 16,
) -> list[dict[str, Any]]:
    """Recover repeated cross-family relationships without naming a bug class."""

    if len(profiles) < 2 or limit < 1 or per_family_pair_limit < 1:
        return []
    support = Counter(
        feature for profile in profiles for feature in set(profile.feature_ids)
    )
    pairs: Counter[tuple[str, str]] = Counter()
    for profile in profiles:
        eligible = sorted(
            feature for feature in set(profile.feature_ids)
            if profile.feature_families.get(feature) not in {
                "cardinality", "outcome", "semantic-state"
            }
        )[:192]
        pairs.update(combinations(eligible, 2))
    candidates: list[tuple[float, tuple[str, str], dict[str, Any]]] = []
    total = len(profiles)
    family_lookup = {
        feature: family
        for profile in profiles
        for feature, family in profile.feature_families.items()
    }
    for (left, right), pair_support in pairs.items():
        if pair_support < 2:
            continue
        lift = pair_support * total / (support[left] * support[right])
        left_family = family_lookup[left]
        right_family = family_lookup[right]
        if left_family == right_family == "operation" and lift <= 1.0:
            continue
        weight = math.sqrt(
            FAMILY_WEIGHTS.get(left_family, 1.0)
            * FAMILY_WEIGHTS.get(right_family, 1.0)
        )
        score = pair_support * max(0.1, lift - 1.0) * weight
        value = {
            "left_feature": left,
            "right_feature": right,
            "left_family": left_family,
            "right_family": right_family,
            "support_count": pair_support,
            "left_support": support[left],
            "right_support": support[right],
            "lift": round(lift, 4),
            "relationship_score": round(score, 4),
            "meaning": "Repeated corpus co-occurrence; no direction or causality is implied.",
        }
        candidates.append((score, (left, right), value))
    selected = []
    family_pair_counts: Counter[tuple[str, str]] = Counter()
    for _, _, value in sorted(candidates, key=lambda item: (-item[0], item[1])):
        family_pair = tuple(sorted((
            str(value["left_family"]), str(value["right_family"]),
        )))
        if family_pair_counts[family_pair] >= per_family_pair_limit:
            continue
        selected.append(value)
        family_pair_counts[family_pair] += 1
        if len(selected) >= limit:
            break
    return selected


def _feature_catalog(
    profiles: Sequence[RunProfile], catalog: Mapping[str, FeatureObservation],
) -> list[dict[str, Any]]:
    support: dict[str, list[str]] = defaultdict(list)
    for profile in profiles:
        for feature in profile.feature_ids:
            support[feature].append(profile.label)
    values = []
    for feature_id, observation in catalog.items():
        value = observation.as_dict()
        value["support_runs"] = sorted(set(support[feature_id]))
        value["support_count"] = len(value["support_runs"])
        values.append(value)
    return sorted(values, key=lambda item: (item["family"], item["feature_id"]))


def semantic_graph(
    runs: Sequence[RunHistory], profiles: Sequence[RunProfile],
    catalog: Mapping[str, FeatureObservation], elements: Sequence[Element],
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def node(node_id: str, kind: str, label: str, **attrs: Any) -> None:
        nodes.setdefault(node_id, {"id": node_id, "kind": kind, "label": label, **attrs})

    def edge(source: str, target: str, relation: str, run: str,
             evidence: Mapping[str, Any] | None = None) -> None:
        slot = edges.setdefault((source, target, relation), {
            "source": source, "target": target, "relation": relation,
            "count": 0, "runs": set(), "evidence": [],
        })
        slot["count"] += 1
        slot["runs"].add(run)
        if evidence is not None and len(slot["evidence"]) < 4:
            slot["evidence"].append(dict(evidence))

    profiles_by_label = {profile.label: profile for profile in profiles}
    for run in runs:
        run_id = _stable_id("run", run.label)
        node(run_id, "run", run.label, role=run.role, group=run.group)
        profile = profiles_by_label[run.label]
        for feature_id in profile.feature_ids:
            observation = catalog[feature_id]
            node(feature_id, "feature", observation.label, family=observation.family)
            edge(run_id, feature_id, "exhibits", run.label)
        previous_action_by_domain: dict[str, str] = {}
        for event in run.events:
            principal_label = _principal(event)
            principal_id = _stable_id("principal", principal_label)
            action_label = _action(event)
            action_id = _stable_id("action", action_label)
            node(principal_id, "principal", principal_label)
            node(action_id, "action", action_label)
            ref = _event_ref(run, event)
            edge(run_id, principal_id, "observes", run.label, ref)
            edge(principal_id, action_id, "performs", run.label, ref)
            domain = _order_domain(event)
            previous_action = previous_action_by_domain.get(domain)
            if previous_action is not None:
                edge(
                    previous_action, action_id, "observed-before", run.label,
                    {**ref, "order_domain": domain},
                )
            previous_action_by_domain[domain] = action_id
            endpoint = event.get("receiver", event.get("target"))
            if endpoint is not None:
                endpoint_label = str(endpoint)
                endpoint_id = _stable_id("endpoint", endpoint_label)
                node(endpoint_id, "endpoint", endpoint_label)
                edge(action_id, endpoint_id, "targets", run.label, ref)
            obj = event.get("object")
            if obj is not None:
                raw_label = str(obj)
                raw_id = _stable_id("object", raw_label)
                generation = str(event.get("generation", "unknown"))
                lifetime_label = f"{raw_label}@{generation}"
                lifetime_id = _stable_id("lifetime", lifetime_label)
                node(raw_id, "object", raw_label)
                node(lifetime_id, "lifetime", lifetime_label, generation=generation)
                edge(lifetime_id, raw_id, "generation-of", run.label, ref)
                edge(action_id, lifetime_id, "acts-on", run.label, ref)
                edge(principal_id, lifetime_id, "observes-lifetime", run.label, ref)
            for field in RESOURCE_FIELDS:
                if field == "object" or event.get(field) is None:
                    continue
                resource_label = f"{field}:{event.get(field)}"
                resource_id = _stable_id("resource", resource_label)
                node(
                    resource_id, "resource", resource_label,
                    resource_type=field,
                )
                edge(action_id, resource_id, "acts-on", run.label, ref)
                edge(principal_id, resource_id, "observes-resource", run.label, ref)

    for element in elements:
        element_id = f"element:{element.element_id}"
        node(element_id, "element", element.title, element_kind=element.kind)
        for evidence in element.evidence:
            label = evidence.get("run")
            if label is None or str(label) not in profiles_by_label:
                continue
            edge(
                element_id, _stable_id("run", str(label)),
                "supported-by", str(label), evidence,
            )

    encoded_edges = []
    for value in edges.values():
        encoded_edges.append({
            **value,
            "runs": sorted(value["runs"]),
        })
    return {
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(
            encoded_edges,
            key=lambda item: (item["source"], item["relation"], item["target"]),
        ),
    }


def build_discovery_bundle(
    runs: Sequence[RunHistory], elements: Sequence[Element], *, spec: str,
    budget: int | None = None,
) -> dict[str, Any]:
    profiles, catalog = profile_runs(runs)
    queue = rank_novelty(profiles, budget=budget)
    family_counts = Counter(
        observation.family for observation in catalog.values()
    )
    contrasts = mine_contrasts(profiles)
    associations = mine_outcome_associations(profiles)
    cooccurrence = mine_feature_cooccurrence(profiles)
    trace_sources = Counter(
        str(event.get("source", "unspecified"))
        for run in runs for event in run.events
    )
    order_domains = Counter(
        _order_domain(event) for run in runs for event in run.events
    )
    secure_rules: Counter[str] = Counter()
    secure_lines = 0
    secure_parsed = 0
    secure_ignored = 0
    for run in runs:
        secure = run.summary.get("secure_trace", {})
        if not isinstance(secure, Mapping):
            continue
        secure_lines += int(secure.get("lines", 0))
        secure_parsed += int(secure.get("parsed_events", 0))
        secure_ignored += int(secure.get("ignored_lines", 0))
        rules = secure.get("rules", {})
        if isinstance(rules, Mapping):
            secure_rules.update({
                str(name): int(count) for name, count in rules.items()
            })
    return {
        "schema": "teeweaver-discovery-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "purpose": (
            "High-throughput dynamic relationship discovery for downstream AI. "
            "No record in this bundle is a vulnerability verdict."
        ),
        "priority_score_meaning": (
            "Greedy marginal semantic coverage, control-unseen evidence, rarity, "
            "and relational richness. It is not severity, CVSS, exploitability, "
            "novelty against private reports, or bounty likelihood."
        ),
        "spec": spec,
        "summary": {
            "runs": len(runs),
            "events": sum(len(run.events) for run in runs),
            "features": len(catalog),
            "feature_families": dict(sorted(family_counts.items())),
            "elements": len(elements),
            "queued_runs": len(queue),
            "contrasts": len(contrasts),
            "outcome_associations": len(associations),
            "feature_cooccurrences": len(cooccurrence),
        },
        "observation_coverage": {
            "trace_sources": dict(sorted(trace_sources.items())),
            "order_domains": dict(sorted(order_domains.items())),
            "secure_log": {
                "lines": secure_lines,
                "parsed_events": secure_parsed,
                "ignored_lines": secure_ignored,
                "parsed_line_fraction": round(
                    secure_parsed / max(1, secure_lines), 4
                ),
                "rules": dict(sorted(secure_rules.items())),
                "boundary": (
                    "Ignored lines are outside the current normalizer, not proof "
                    "that the underlying transitions are irrelevant."
                ),
            },
        },
        "discovery_queue": [entry.as_dict() for entry in queue],
        "profiles": [profile.as_dict() for profile in profiles],
        "feature_catalog": _feature_catalog(profiles, catalog),
        "differential_mining": {
            "contrasts": contrasts,
            "outcome_associations": associations,
            "feature_cooccurrences": cooccurrence,
        },
        "elements": [element.as_dict() for element in elements],
        "semantic_graph": semantic_graph(runs, profiles, catalog, elements),
        "ai_experiment_contract": {
            "input": "Select one queued run and one or more feature IDs.",
            "output_schema": {
                "hypothesis": "string",
                "selected_runs": ["run-label"],
                "target_features": ["feature-id"],
                "intervention": {
                    "kind": (
                        "delay|repeat|schedule-order|identity-substitution|"
                        "reset-replay|persistence-cut"
                    ),
                    "target": "action/resource/endpoint",
                    "parameters": {},
                },
                "controls": ["control description"],
                "requested_observations": ["event or state to capture"],
            },
            "boundary": (
                "TEEWeaver executes and records requested interventions. "
                "The downstream AI or researcher interprets security meaning."
            ),
        },
    }


def render_discovery_markdown(bundle: Mapping[str, Any]) -> str:
    summary = bundle["summary"]
    coverage = bundle.get("observation_coverage", {})
    secure = coverage.get("secure_log", {}) if isinstance(coverage, Mapping) else {}
    lines = [
        "# TEEWeaver discovery bundle", "",
        f"{summary['runs']} runs, {summary['events']} events, "
        f"{summary['features']} semantic features, {summary['elements']} mined elements.",
        "",
        "Priority scores rank dynamic follow-up value. They are not vulnerability "
        "severity or exploitability.", "", "## Discovery queue", "",
    ]
    for entry in bundle["discovery_queue"]:
        lines.extend((
            f"### {entry['rank']}. {entry['run']} — {entry['priority_score']}", "",
            f"- Marginal features: {len(entry['marginal_features'])}",
            f"- Control-unseen features: {len(entry['control_unseen_features'])}",
            f"- Relational families: {', '.join(entry['relational_families']) or 'none'}",
        ))
        if entry.get("contrast_run"):
            lines.append(
                f"- Contrast: `{entry['contrast_run']}` ({entry['contrast_kind']})"
            )
        for reason in entry["reasons"]:
            lines.append(f"- {reason}")
        lines.append("")
    lines.extend(("## Feature families", ""))
    for family, count in summary["feature_families"].items():
        lines.append(f"- `{family}`: {count}")
    if secure and int(secure.get("lines", 0)):
        lines.extend((
            "", "## Observation coverage", "",
            f"Secure-log normalization emitted {secure['parsed_events']} events "
            f"from {secure['lines']} lines "
            f"({secure['parsed_line_fraction']:.2%} parsed-line coverage).",
            "",
            str(secure.get("boundary", "")),
        ))
    lines.extend((
        "", "## Interpretation boundary", "",
        "This artifact exposes runtime relationships and experiment surfaces. "
        "It deliberately does not assign CWE, CVSS, exploitability, or a "
        "vulnerability verdict.", "",
    ))
    return "\n".join(lines)
