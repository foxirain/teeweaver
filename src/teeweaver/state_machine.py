"""Normalized boundary coverage and evidence-derived experiment synthesis."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, replace
from typing import Any, Iterable, Mapping, Sequence

from .events import Event


TRANSIENT_ERRNOS = {4, 11, 16}  # EINTR, EAGAIN, EBUSY
CREATE_OPS = {
    "ffa_share", "shm_register", "rpc_issue", "operation_issue",
    "object_verify", "storage_ack",
}
USE_OPS = {
    "ffa_retrieve", "ffa_access", "ffa_call_issue", "ffa_direct_message", "shm_use",
    "rpc_reply", "rpc_accept", "operation_complete", "object_consume",
    "storage_observe",
}
CLOSE_OPS = {
    "ffa_relinquish", "ffa_reclaim", "ffa_reclaim_attempt", "shm_release",
    "session_close", "operation_cancel",
}
IDENTITY_FIELDS = ("object", "request", "operation", "key")

# Security-property frontier, intentionally expressed as relationships rather
# than OP-TEE source locations or historical bug triggers.  A target is
# covered only when a real trace reaches every listed dimension.
FRONTIER_TARGETS: tuple[Mapping[str, Any], ...] = (
    {
        "id": "foreign-live-identity-use",
        "priority": 100,
        "requires": {
            "principal_relation": {"cross-principal"},
            "phase": {"consume-or-use", "close-or-release"},
            "lifecycle_before": {"live", "verified", "acknowledged"},
            "authorization_relation": {"non-owner", "foreign-receiver"},
        },
        "property": "A live identity is bound to its authorized principal before lookup or mutation.",
    },
    {
        "id": "stale-generation-use",
        "priority": 99,
        "requires": {
            "phase": {"consume-or-use", "close-or-release"},
            "generation_relation": {"stale-generation"},
        },
        "property": "A raw identity cannot authorize work from an earlier lifetime.",
    },
    {
        "id": "closed-object-use",
        "priority": 98,
        "requires": {
            "phase": {"consume-or-use"},
            "lifecycle_before": {"closed", "partially-closed"},
        },
        "property": "Use after terminal or partial cleanup is rejected atomically.",
    },
    {
        "id": "cross-epoch-use",
        "priority": 97,
        "requires": {
            "phase": {"consume-or-use", "close-or-release"},
            "epoch_relation": {"cross-epoch"},
        },
        "property": "Pre-reset authority or state does not silently survive into a new epoch.",
    },
    {
        "id": "authenticated-byte-drift",
        "priority": 97,
        "requires": {
            "authorization_relation": {"authenticated-bytes-drift"},
        },
        "property": "Consumed bytes are exactly those authenticated for this generation.",
    },
    {
        "id": "failure-then-use",
        "priority": 94,
        "requires": {
            "phase": {"consume-or-use"},
            "lifecycle_before": {"observed-after-failure"},
        },
        "property": "A failed transition leaves no partial authority consumable by a later call.",
    },
    {
        "id": "duplicate-terminal",
        "priority": 91,
        "requires": {
            "phase": {"close-or-release"},
            "lifecycle_before": {"closed", "partially-closed"},
        },
        "property": "Terminal transitions are idempotent or reject duplicates without underflow.",
    },
    {
        "id": "wrong-context-rpc-accept",
        "priority": 96,
        "requires": {
            "protocol": {"rpc"},
            "operation": {"rpc_accept"},
            "authorization_relation": {"non-owner"},
        },
        "property": "An RPC result is consumed only by its issuing context.",
    },
)

FRONTIER_ADAPTERS: Mapping[str, Mapping[str, Any]] = {
    "foreign-live-identity-use": {
        "adapter": "multi-principal identity broker",
        "minimum_events": ["create(A, object)", "use(B, object)", "post-use liveness"],
    },
    "stale-generation-use": {
        "adapter": "allocator reuse controller with delayed/replayed request bytes",
        "minimum_events": ["create generation N", "close N", "reuse as N+1", "replay N"],
    },
    "closed-object-use": {
        "adapter": "lifecycle replay adapter",
        "minimum_events": ["accepted use", "terminal close", "identical replay"],
    },
    "cross-epoch-use": {
        "adapter": "cold-reset snapshot/restore backend",
        "minimum_events": ["acknowledge", "reset", "restore", "observe/use"],
    },
    "authenticated-byte-drift": {
        "adapter": "Secure-World verify/consume digest tap plus REE byte mutation",
        "minimum_events": ["object_verify digest A", "mutation", "object_consume digest B"],
    },
    "failure-then-use": {
        "adapter": "fault injection plus post-failure state snapshot",
        "minimum_events": ["pre-state", "failed transition", "follow-up use", "post-state"],
    },
    "duplicate-terminal": {
        "adapter": "exact terminal-request replay",
        "minimum_events": ["terminal success", "duplicate terminal", "fresh lifecycle control"],
    },
    "wrong-context-rpc-accept": {
        "adapter": "RPC response broker plus Secure-World consumption marker",
        "minimum_events": ["issue A/B", "cross-bind reply", "accept/consume context"],
    },
}


def _principal(event: Event) -> str:
    process = event.get("process")
    if process is not None:
        return f"normal-world-{process}"
    actor = str(event.actor)
    if actor.startswith("ffa-client-"):
        return "normal-world-" + actor.removeprefix("ffa-client-")
    return actor


def _domain(value: Any) -> str:
    text = str(value or "unknown").lower()
    if text in {"unknown", "none", ""}:
        return "unknown"
    if text.isdigit() or text.startswith(("sp-", "secure-partition")):
        return "secure-endpoint"
    if any(token in text for token in ("secure", "thread", "ta-", "ldelf")):
        return "secure-world"
    if any(token in text for token in (
        "ree", "normal", "supplicant", "client", "ffa-client", "process",
    )):
        return "normal-world"
    if any(token in text for token in ("platform", "reset", "power")):
        return "platform"
    if any(token in text for token in ("session", "owner")):
        return "logical-owner"
    return "other-principal"


def _protocol(op: str) -> str:
    for prefix in ("ffa_", "rpc_", "shm_", "storage_", "object_", "operation_"):
        if op.startswith(prefix):
            return prefix[:-1]
    return "platform" if op == "reset" else "other"


def _identity(event: Event) -> tuple[str, str] | None:
    for field in IDENTITY_FIELDS:
        value = event.get(field)
        if value is not None:
            kind = {
                "object": (
                    "ffa-handle" if event.op.startswith("ffa_") else
                    "shared-memory" if event.op.startswith("shm_") else
                    "authenticated-object"
                ),
                "request": "rpc-request",
                "operation": "client-operation",
                "key": "persistent-object",
            }[field]
            return kind, str(value)
    return None


def _identity_field(event: Event) -> str | None:
    return next((field for field in IDENTITY_FIELDS
                 if event.get(field) is not None), None)


def _state_identity(event: Event) -> tuple[str, str] | None:
    """Identity key at its actual allocation scope.

    Linux TEE supplicant request IDs are process-local. Treating request ``1``
    from two supplicants as one live object creates exactly the false cross-
    principal dependency that the discovery layer is meant to eliminate.
    FF-A handles and traced SHM identities remain global in this model.
    """

    identity = _identity(event)
    if identity and identity[0] == "rpc-request":
        return identity[0], f"{_principal(event)}:{identity[1]}"
    return identity


def _peer(event: Event) -> Any:
    for key in ("receiver", "owner", "session", "claims_request"):
        if event.get(key) is not None:
            return event.get(key)
    return None


def _operation(event: Event) -> str:
    if event.get("action") is not None:
        return f"{event.op}:action={event.get('action')}"
    if event.get("func") is not None:
        return f"{event.op}:func={event.get('func')}"
    return event.op


def _phase(op: str) -> str:
    if op in CREATE_OPS:
        return "create-or-authenticate"
    if op in USE_OPS:
        return "consume-or-use"
    if op in CLOSE_OPS:
        return "close-or-release"
    if op == "reset":
        return "epoch-boundary"
    if op.endswith(("_fail", "_fault")):
        return "fault"
    return "transition"


def _fault_family(event: Event) -> str:
    value = str(event.get("fault", "none"))
    if value in {"", "none", "0"}:
        return "none"
    for prefix in ("delay", "swap", "flip", "force", "duplicate", "replay"):
        if value.startswith(prefix):
            return prefix
    return "other"


def _outcome(event: Event, transient: bool) -> str:
    result = event.get("ioctl_result")
    if result is None:
        return "observed"
    if int(result) >= 0:
        return "success"
    errno = abs(int(event.get("ioctl_errno", 0)))
    if transient:
        return "retryable-failure"
    if errno in {1, 13}:
        return "authorization-failure"
    if errno in TRANSIENT_ERRNOS:
        return "unrecovered-transient-failure"
    return "failure"


def _transient_retries(events: Sequence[Event], window: int = 64) -> set[int]:
    """Return failed events followed by the same principal/action succeeding.

    This prevents an ordinary EBUSY/EAGAIN retry loop from becoming semantic
    novelty merely because the scheduler moved the first attempt.
    """

    transient: set[int] = set()
    for index, event in enumerate(events):
        if int(event.get("ioctl_result", 0)) >= 0:
            continue
        if abs(int(event.get("ioctl_errno", 0))) not in TRANSIENT_ERRNOS:
            continue
        key = (_principal(event), _operation(event), _identity(event))
        for later in events[index + 1:index + 1 + window]:
            later_key = (_principal(later), _operation(later), _identity(later))
            if later_key == key and int(later.get("ioctl_result", -1)) >= 0:
                transient.add(event.seq)
                break
    return transient


@dataclass(frozen=True, slots=True)
class BoundaryTuple:
    """Identity-renaming-resistant coverage for one trust-boundary transition."""

    protocol: str
    operation: str
    phase: str
    source_domain: str
    destination_domain: str
    principal_relation: str
    object_kind: str
    lifecycle_before: str
    generation_relation: str
    epoch_relation: str
    authorization_relation: str
    outcome: str
    fault_family: str

    def signature(self) -> str:
        encoded = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode()).hexdigest()[:20]

    def as_dict(self) -> dict[str, str]:
        value = asdict(self)
        value["signature"] = self.signature()
        return value


@dataclass(frozen=True, slots=True)
class ObservedBoundary:
    seq: int
    tuple: BoundaryTuple

    def as_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, **self.tuple.as_dict()}


def observe_boundaries(events: Iterable[Event]) -> list[ObservedBoundary]:
    """Project a raw history into security-boundary tuples.

    Raw PIDs, handles, request IDs, timestamps, and absolute generations are
    intentionally absent.  Relations (foreign/same principal, stale/current
    generation, pre/post reset, verified/changed bytes) remain.
    """

    history = list(events)
    transient = _transient_retries(history)
    epoch = 0
    state: dict[tuple[str, str], dict[str, Any]] = {}
    observed: list[ObservedBoundary] = []
    for event in history:
        identity = _state_identity(event)
        obj_kind, obj = identity or ("none", "none")
        key = (obj_kind, obj)
        previous = state.get(key)
        generation = int(event.get("generation", 0))
        if previous is None:
            generation_relation = "first-observation"
            lifecycle = "absent"
            epoch_relation = "current-epoch"
        else:
            lifecycle = str(previous.get("lifecycle", "observed-without-create"))
            previous_generation = int(previous.get("generation", 0))
            if generation < previous_generation:
                generation_relation = "stale-generation"
            elif generation > previous_generation:
                generation_relation = "new-generation"
            else:
                generation_relation = "current-generation"
            epoch_relation = (
                "cross-epoch" if int(previous.get("epoch", epoch)) != epoch
                else "current-epoch"
            )

        source = _principal(event)
        peer = _peer(event)
        peer_text = None if peer is None else str(peer)
        if peer_text is None:
            relation = "no-peer"
        elif source == peer_text:
            relation = "same-principal"
        else:
            relation = "cross-principal"

        authorization = "not-observed"
        if (previous and previous.get("receiver") is not None
                and event.get("receiver") is not None):
            authorization = (
                "receiver-match"
                if str(event.get("receiver")) == str(previous["receiver"])
                else "foreign-receiver"
            )
        elif previous and previous.get("owner") is not None:
            expected = str(previous["owner"])
            authorization = "owner-match" if source == expected else "non-owner"
        if event.op == "object_consume" and previous:
            authorization = (
                "authenticated-bytes-match"
                if event.get("digest") == previous.get("digest")
                else "authenticated-bytes-drift"
            )

        outcome = _outcome(event, event.seq in transient)
        boundary = BoundaryTuple(
            protocol=_protocol(event.op),
            operation=_operation(event),
            phase=_phase(event.op),
            source_domain=_domain(source),
            destination_domain=_domain(peer),
            principal_relation=relation,
            object_kind=obj_kind,
            lifecycle_before=lifecycle,
            generation_relation=generation_relation,
            epoch_relation=epoch_relation,
            authorization_relation=authorization,
            outcome=outcome,
            fault_family=_fault_family(event),
        )
        observed.append(ObservedBoundary(event.seq, boundary))

        if event.op == "reset":
            epoch += 1
            continue
        if identity is None:
            continue
        next_state = dict(previous or {})
        next_state.update({"generation": generation, "epoch": epoch})
        if event.op in CREATE_OPS:
            next_state["lifecycle"] = (
                "verified" if event.op == "object_verify" else
                "acknowledged" if event.op == "storage_ack" else "live"
            )
            next_state["owner"] = event.get("owner", source)
            if event.get("receiver") is not None:
                next_state["receiver"] = event.get("receiver")
            if event.get("digest") is not None:
                next_state["digest"] = event.get("digest")
        elif event.op in {"ffa_relinquish", "operation_cancel"}:
            next_state["lifecycle"] = "partially-closed"
        elif event.op in CLOSE_OPS:
            next_state["lifecycle"] = "closed"
        elif event.op in USE_OPS and not next_state.get("lifecycle"):
            next_state["lifecycle"] = "observed-without-create"
        if outcome in {
            "failure", "authorization-failure",
            "unrecovered-transient-failure",
        }:
            next_state["lifecycle"] = "observed-after-failure"
        state[key] = next_state
    return observed


@dataclass(frozen=True, slots=True)
class ExperimentProposal:
    proposal_id: str
    family: str
    title: str
    priority: int
    source_run: str
    anchor_seqs: tuple[int, ...]
    target_boundary: Mapping[str, Any]
    mutations: tuple[Mapping[str, Any], ...]
    execution_mode: str
    rationale: str
    prerequisites: tuple[str, ...]
    expected_oracle: str
    falsifier: str
    support_runs: tuple[str, ...]
    not_a_finding: bool = True

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["target_boundary"] = dict(self.target_boundary)
        value["mutations"] = [dict(item) for item in self.mutations]
        return value


def _proposal(
    family: str,
    title: str,
    priority: int,
    source_run: str,
    anchors: Sequence[int],
    target: Mapping[str, Any],
    mutations: Sequence[Mapping[str, Any]],
    execution_mode: str,
    rationale: str,
    prerequisites: Sequence[str],
    oracle: str,
    falsifier: str,
) -> ExperimentProposal:
    def stable_mutation(mutation: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: value for key, value in mutation.items()
            if not key.endswith("_seq")
            and key not in {"raw_value", "replacement"}
        }

    semantic = {
        "family": family,
        "target": {
            key: target.get(key) for key in (
                "operation", "object_kind", "lifecycle_before",
                "generation_relation", "epoch_relation",
                "authorization_relation", "principal_relation",
            )
        },
        "mutations": [stable_mutation(mutation) for mutation in mutations],
    }
    suffix = hashlib.sha256(json.dumps(
        semantic, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()[:12]
    return ExperimentProposal(
        f"{family}-{suffix}", family, title, max(0, min(100, priority)),
        source_run, tuple(anchors), dict(target), tuple(dict(x) for x in mutations),
        execution_mode, rationale, tuple(prerequisites), oracle, falsifier,
        (source_run,),
    )


def _run_label(run: Any, index: int) -> str:
    return str(getattr(run, "label", f"run-{index}"))


def _run_events(run: Any) -> Sequence[Event]:
    return tuple(getattr(run, "events", run))


def synthesize_experiments(
    runs: Sequence[Any], *, budget: int = 128, per_family: int = 24
) -> list[ExperimentProposal]:
    """Generate semantic mutations from runtime structure, not known bug recipes."""

    if budget < 1 or per_family < 1:
        raise ValueError("budget and per_family must be positive")
    candidates: list[ExperimentProposal] = []
    for run_index, run in enumerate(runs):
        label = _run_label(run, run_index)
        events = _run_events(run)
        tuples = {item.seq: item.tuple.as_dict() for item in observe_boundaries(events)}
        by_kind: dict[str, list[tuple[Event, str, str]]] = defaultdict(list)
        by_object: dict[tuple[str, str], list[Event]] = defaultdict(list)
        principals = sorted({_principal(event) for event in events})
        receivers = sorted({str(event.get("receiver")) for event in events
                            if event.get("receiver") is not None})
        for event in events:
            identity = _identity(event)
            state_identity = _state_identity(event)
            if identity and state_identity:
                by_kind[identity[0]].append(
                    (event, identity[1], state_identity[1])
                )
                by_object[state_identity].append(event)

        # Transpose one live identity into a peer's otherwise-valid operation.
        for kind, observations in by_kind.items():
            objects: dict[str, tuple[Event, str]] = {}
            for event, raw_obj, scoped_obj in observations:
                objects.setdefault(scoped_obj, (event, raw_obj))
            if len(objects) < 2:
                continue
            ordered = list(objects.items())
            for (_, (left, left_raw)), (right_obj, (right, right_raw)) in zip(
                ordered, ordered[1:]
            ):
                target = next((event for event, _, scoped_obj in observations
                               if scoped_obj == right_obj
                               and event.op in USE_OPS | CLOSE_OPS), None)
                if target is None or left_raw == right_raw:
                    continue
                candidates.append(_proposal(
                    "cross-principal-identity-transposition",
                    "Use one principal's live identity in another principal's transition",
                    94 if _principal(left) != _principal(right) else 84,
                    label, (left.seq, target.seq), tuples.get(target.seq, {}),
                    ({
                        "kind": "replace-identity",
                        "target_seq": target.seq,
                        "field": _identity_field(target) or "object",
                        "source_seq": left.seq,
                        "raw_value": right_raw,
                        "replacement": left_raw,
                        "preserve": ["receiver", "action", "generation", "payload"],
                    },),
                    "adapter-required",
                    "The identities are independently valid, but their principal binding has not "
                    "been exercised under transposition.",
                    ("Keep both objects live at the mutation point.",
                     "Hold request bytes and scheduling fixed except for identity."),
                    "reject foreign identity without Secure-World crash or state mutation",
                    "The receiving path rejects the foreign identity and the original owner can still complete its lifecycle.",
                ))

        # Substitute a peer identity while preserving object and request bytes.
        if len(principals) > 1 or len(receivers) > 1:
            for event in events:
                if event.op not in USE_OPS | CLOSE_OPS:
                    continue
                if _protocol(event.op) not in {
                    "ffa", "rpc", "shm", "operation", "object"
                }:
                    continue
                field = "receiver" if event.get("receiver") is not None else "actor"
                alternatives = receivers if field == "receiver" else principals
                original = str(event.get(field, event.actor))
                replacement = next((item for item in alternatives if item != original), None)
                if replacement is None:
                    continue
                candidates.append(_proposal(
                    "cross-principal-context-substitution",
                    "Move a valid transition to a different security principal",
                    90, label, (event.seq,), tuples.get(event.seq, {}),
                    ({"kind": "replace-principal", "target_seq": event.seq,
                      "field": field, "raw_value": original,
                      "replacement": replacement,
                      "preserve": ["object", "generation", "payload"]},),
                    "adapter-required",
                    "A valid operation/object pair is retargeted across the observed principal boundary.",
                    ("The replacement principal must be independently reachable.",),
                    "authorization check binds object and operation to the original principal",
                    "The substituted principal is rejected before lookup/use and no shared state changes.",
                ))
                break

        for identity, object_events in by_object.items():
            closes = [event for event in object_events if event.op in CLOSE_OPS]
            uses = [event for event in object_events if event.op in USE_OPS]
            creates = [event for event in object_events if event.op in CREATE_OPS]
            for close in closes[:2]:
                source = next((event for event in reversed(uses)
                               if event.seq < close.seq), None)
                if source is not None:
                    candidates.append(_proposal(
                        "lifecycle-epoch-crossing",
                        "Replay a valid pre-close transition after its lifecycle ends",
                        92, label, (source.seq, close.seq), tuples.get(source.seq, {}),
                        ({"kind": "delay-and-replay", "source_seq": source.seq,
                          "insert_after_seq": close.seq,
                          "preserve": ["identity", "generation", "principal", "payload"]},),
                        "adapter-required",
                        "The operation is valid in one lifetime and is moved unchanged across its close boundary.",
                        ("Capture the exact accepted pre-close bytes.",
                         "Observe both protocol response and subsequent owner lifecycle."),
                        "stale generation/lifetime is rejected atomically",
                        "The replay is rejected and a fresh operation on the same object remains unaffected.",
                    ))
                duplicate_mutation: dict[str, Any] = {
                    "kind": "duplicate", "target_seq": close.seq,
                    "preserve": ["identity", "generation", "principal", "payload"],
                }
                duplicate_mode = "adapter-required"
                if (close.op == "ffa_reclaim_attempt"
                        and close.get("occurrence") is not None):
                    duplicate_mode = "existing-runner"
                    duplicate_mutation["rule"] = (
                        f"ffa_duplicate:reclaim:{close.get('occurrence')}"
                    )
                candidates.append(_proposal(
                    "duplicate-terminal-transition",
                    "Repeat a terminal transition at the same security boundary",
                    79, label, (close.seq,), tuples.get(close.seq, {}),
                    (duplicate_mutation,), duplicate_mode,
                    "Terminal operations are where refcounts, membership, and ownership are usually detached.",
                    ("The first transition must complete before the duplicate is issued.",),
                    "duplicate close is rejected without underflow, panic, or resurrection",
                    "The duplicate receives the documented error and later allocation/use behaves like the clean control.",
                ))
            generations = sorted({int(event.get("generation", 0)) for event in object_events})
            if len(generations) > 1 and uses:
                oldest = min(generations)
                stale = next((event for event in uses
                              if int(event.get("generation", 0)) == oldest), uses[0])
                newest_create = next((event for event in reversed(creates)
                                      if int(event.get("generation", 0)) == max(generations)), None)
                if newest_create:
                    candidates.append(_proposal(
                        "aba-generation-replay",
                        "Replay an old-generation operation after identity reuse",
                        96, label, (stale.seq, newest_create.seq), tuples.get(stale.seq, {}),
                        ({"kind": "replay-old-generation", "source_seq": stale.seq,
                          "insert_after_seq": newest_create.seq,
                          "preserve": ["raw_identity", "old_generation", "payload"]},),
                        "adapter-required",
                        "The same visible identity has multiple observed lifetimes.",
                        ("Force or wait for raw identity reuse.",
                         "Record the new owner's clean control."),
                        "generation binding rejects stale bytes without affecting the new owner",
                        "Old-generation input is rejected and the new generation remains usable and isolated.",
                    ))

        # Move the next accepted operation through a failed transition.
        for index, failed in enumerate(events):
            if int(failed.get("ioctl_result", 0)) >= 0 and failed.op != "operation_fail":
                continue
            identity = _state_identity(failed)
            later = next((event for event in events[index + 1:index + 65]
                          if event.op in USE_OPS and (
                              identity is None or _state_identity(event) == identity
                          )), None)
            if later is None:
                continue
            failure_mutation: dict[str, Any] = {
                "kind": "force-failure", "target_seq": failed.seq
            }
            failure_mode = "adapter-required"
            if (failed.op == "rpc_reply" and failed.get("func") is not None
                    and failed.get("occurrence") is not None):
                failure_mode = "existing-runner"
                failure_mutation["rule"] = (
                    f"force_ret:{failed.get('func')}:{failed.get('occurrence')}:"
                    "0xffff0000"
                )
            candidates.append(_proposal(
                "failure-continuation-probe",
                "Continue through state touched by a failed boundary transition",
                86, label, (failed.seq, later.seq), tuples.get(later.seq, {}),
                (failure_mutation,
                 {"kind": "preserve-followup", "target_seq": later.seq,
                  "preserve": ["identity", "principal", "payload"]}),
                failure_mode,
                "Failure atomicity is observable only by a follow-up transition through the same state.",
                ("Snapshot the object/endpoint before failure and after follow-up.",),
                "failed transition is atomic or fully compensated before follow-up",
                "The post-failure snapshot and behavior match the unmodified clean control.",
            ))
            break

        resets = [event for event in events if event.op == "reset"]
        for reset in resets[:1]:
            before = next((event for event in reversed(events[:events.index(reset)])
                           if _identity(event)), None)
            if before:
                candidates.append(_proposal(
                    "reset-epoch-replay",
                    "Replay acknowledged state or input across a reset epoch",
                    97, label, (before.seq, reset.seq), tuples.get(before.seq, {}),
                    ({"kind": "snapshot-before", "target_seq": before.seq},
                     {"kind": "restore-after-reset", "target_seq": reset.seq}),
                    "existing-runner" if before.op.startswith("storage_") else "adapter-required",
                    "Reset separates trusted epochs while the REE can preserve and replay old bytes.",
                    ("Use a passing fresh-state control.", "Pin the same Secure-World binary and keys."),
                    "freshness state rejects pre-reset rollback/replay",
                    "The restored state is rejected or resolves to the latest acknowledged value.",
                ))

        # Reorder adjacent cross-principal operations that touch the same object.
        interesting = [event for event in events if _state_identity(event)]
        for left, right in zip(interesting, interesting[1:]):
            if (_state_identity(left) != _state_identity(right)
                    or _principal(left) == _principal(right)):
                continue
            candidates.append(_proposal(
                "dependent-transition-reorder",
                "Reverse two dependent cross-principal transitions",
                82, label, (left.seq, right.seq), tuples.get(right.seq, {}),
                ({"kind": "barrier-reorder", "first_seq": left.seq,
                  "second_seq": right.seq, "orders": ["AB", "BA"]},),
                "adapter-required",
                "The two transitions share identity/lifetime state but originate from different principals.",
                ("Run AB and BA with identical bytes and clean controls.",),
                "both legal orders preserve ownership, lifetime, and isolation invariants",
                "Repeated AB/BA controls produce equivalent snapshots and outcomes.",
            ))
            break

    # Semantic deduplication avoids spending the campaign on PID/handle variants.
    best: dict[str, ExperimentProposal] = {}
    support: dict[str, set[str]] = defaultdict(set)
    for candidate in candidates:
        support[candidate.proposal_id].add(candidate.source_run)
        previous = best.get(candidate.proposal_id)
        if previous is None or candidate.priority > previous.priority:
            best[candidate.proposal_id] = candidate
    for proposal_id, candidate in tuple(best.items()):
        runs_for_candidate = tuple(sorted(support[proposal_id]))
        best[proposal_id] = replace(
            candidate,
            priority=min(100, candidate.priority + min(4, len(runs_for_candidate) - 1)),
            support_runs=runs_for_candidate,
        )
    buckets: dict[str, list[ExperimentProposal]] = defaultdict(list)
    for candidate in best.values():
        buckets[candidate.family].append(candidate)
    selected: list[ExperimentProposal] = []
    for family in sorted(buckets):
        selected.extend(sorted(
            buckets[family], key=lambda item: (-item.priority, item.proposal_id)
        )[:per_family])
    return sorted(selected, key=lambda item: (-item.priority, item.family,
                                               item.proposal_id))[:budget]


def coverage_report(runs: Sequence[Any], *, saturation_window: int = 5) -> dict[str, Any]:
    """Return boundary coverage, novelty growth, and a pivot/continue decision."""

    seen: set[str] = set()
    tuples: dict[str, BoundaryTuple] = {}
    growth: list[dict[str, Any]] = []
    dimensions: dict[str, Counter[str]] = defaultdict(Counter)
    for index, run in enumerate(runs):
        boundaries = observe_boundaries(_run_events(run))
        run_signatures = {item.tuple.signature() for item in boundaries}
        new = run_signatures - seen
        seen |= run_signatures
        for item in boundaries:
            signature = item.tuple.signature()
            tuples[signature] = item.tuple
            for key, value in asdict(item.tuple).items():
                dimensions[key][str(value)] += 1
        growth.append({
            "run": _run_label(run, index),
            "tuples": len(run_signatures),
            "new_tuples": len(new),
            "cumulative_tuples": len(seen),
        })

    recent = growth[-saturation_window:] if saturation_window > 0 else []
    recent_gain = sum(item["new_tuples"] for item in recent)
    recent_average = recent_gain / len(recent) if recent else 0.0
    denominator = max(1, len(seen))
    saturated = len(growth) >= saturation_window and (
        recent_gain == 0
        or (recent_average < 2.0 and recent_gain / denominator < 0.02)
    )
    covered_relations = set(dimensions["principal_relation"])
    covered_generations = set(dimensions["generation_relation"])
    covered_epochs = set(dimensions["epoch_relation"])
    gaps: list[str] = []
    if "cross-principal" not in covered_relations:
        gaps.append("cross-principal identity/context transitions")
    if not ({"stale-generation", "new-generation"} & covered_generations):
        gaps.append("identity reuse across lifecycle generations")
    if "cross-epoch" not in covered_epochs:
        gaps.append("operations carrying state across reset epochs")
    if "authenticated-bytes-drift" not in set(dimensions["authorization_relation"]):
        gaps.append("authentication-to-consumption byte drift")
    recommendations = (
        ["pivot to a new boundary/workload family; unchanged scheduling is saturated"]
        if saturated else
        ["continue only plans that target a previously unseen boundary tuple"]
    )
    recommendations.extend(f"add coverage for {gap}" for gap in gaps)
    frontier: list[dict[str, Any]] = []
    for target in FRONTIER_TARGETS:
        requirements = target["requires"]
        matching = [
            value for value in tuples.values()
            if all(getattr(value, field) in accepted
                   for field, accepted in requirements.items())
        ]
        frontier.append({
            "id": target["id"],
            "priority": target["priority"],
            "covered": bool(matching),
            "matching_tuples": len(matching),
            "requires": {
                key: sorted(value) for key, value in requirements.items()
            },
            "property": target["property"],
        })
    uncovered_frontier = [item for item in frontier if not item["covered"]]
    recommendations.extend(
        f"target frontier {item['id']}: {item['property']}"
        for item in uncovered_frontier[:4]
    )
    return {
        "schema": "teeweaver-boundary-coverage-v1",
        "unique_boundary_tuples": len(seen),
        "events_projected": sum(sum(counter.values()) for key, counter in dimensions.items()
                                if key == "protocol"),
        "dimensions": {
            key: dict(sorted(counter.items())) for key, counter in sorted(dimensions.items())
        },
        "growth": growth,
        "saturation": {
            "window": saturation_window,
            "recent_gain": recent_gain,
            "recent_average": round(recent_average, 3),
            "saturated": saturated,
        },
        "coverage_gaps": gaps,
        "security_frontier": frontier,
        "frontier_covered": sum(item["covered"] for item in frontier),
        "frontier_total": len(frontier),
        "recommendations": recommendations,
        "tuples": [tuples[key].as_dict() for key in sorted(tuples)],
    }


def _proposal_frontier_targets(proposal: ExperimentProposal) -> tuple[str, ...]:
    protocol = str(proposal.target_boundary.get("protocol", ""))
    mapping = {
        "aba-generation-replay": ("stale-generation-use",),
        "lifecycle-epoch-crossing": ("stale-generation-use", "closed-object-use"),
        "failure-continuation-probe": ("failure-then-use",),
        "duplicate-terminal-transition": ("duplicate-terminal",),
        "reset-epoch-replay": ("cross-epoch-use",),
    }
    if proposal.family in {
        "cross-principal-identity-transposition",
        "cross-principal-context-substitution",
    }:
        targets = ["foreign-live-identity-use"]
        if protocol == "rpc":
            targets.append("wrong-context-rpc-accept")
        return tuple(targets)
    return mapping.get(proposal.family, ())


def _sink_signature(protocol: str, operation: str, object_kind: str) -> str:
    normalized = operation
    if protocol == "ffa" and ":action=" in operation:
        normalized = "ffa-message:" + operation.split(":action=", 1)[1]
    return f"{protocol}|{normalized}|{object_kind}"


def _observed_target_symptom_sinks(runs: Sequence[Any]) -> dict[str, set[str]]:
    sinks: dict[str, set[str]] = defaultdict(set)
    for index, run in enumerate(runs):
        summary = getattr(run, "summary", {})
        if not isinstance(summary, Mapping) or not summary.get("target_symptoms"):
            continue
        events = _run_events(run)
        anchor = next((event for event in reversed(events)
                       if event.op == "ffa_call_issue"), None)
        if anchor is None:
            anchor = next((event for event in reversed(events)
                           if event.op in USE_OPS | CLOSE_OPS), None)
        if anchor is None:
            continue
        identity = _identity(anchor)
        signature = _sink_signature(
            _protocol(anchor.op), _operation(anchor),
            identity[0] if identity else "none",
        )
        sinks[signature].add(_run_label(run, index))
    return sinks


def proposal_report(
    runs: Sequence[Any], *, budget: int = 128,
    coverage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    proposals = synthesize_experiments(runs, budget=budget)
    coverage_value = coverage or coverage_report(runs)
    symptom_sinks = _observed_target_symptom_sinks(runs)
    frontier_state = {
        str(item["id"]): bool(item["covered"])
        for item in coverage_value.get("security_frontier", ())
    }
    ranked: list[dict[str, Any]] = []
    for proposal in proposals:
        value = proposal.as_dict()
        targets = _proposal_frontier_targets(proposal)
        uncovered = tuple(target for target in targets
                          if not frontier_state.get(target, False))
        if uncovered:
            adjustment = 5
            status = "targets-uncovered-frontier"
        elif targets:
            adjustment = -10
            status = "frontier-already-covered"
        else:
            adjustment = -3
            status = "exploratory-no-frontier-binding"
        if proposal.execution_mode == "adapter-required":
            adjustment -= 1
        sink_signature = _sink_signature(
            str(proposal.target_boundary.get("protocol", "")),
            str(proposal.target_boundary.get("operation", "")),
            str(proposal.target_boundary.get("object_kind", "none")),
        )
        overlap_runs = tuple(sorted(symptom_sinks.get(sink_signature, ())))
        if overlap_runs:
            adjustment -= 15
        value.update({
            "base_priority": proposal.priority,
            "effective_priority": max(0, min(100, proposal.priority + adjustment)),
            "frontier_targets": list(targets),
            "uncovered_frontier_targets": list(uncovered),
            "frontier_status": status,
            "ranking_adjustment": adjustment,
            "dynamic_sink_signature": sink_signature,
            "validated_sink_overlap": bool(overlap_runs),
            "overlap_source_runs": list(overlap_runs),
        })
        ranked.append(value)
    ranked.sort(key=lambda item: (
        -int(item["effective_priority"]),
        -int(item["base_priority"]),
        str(item["family"]),
        str(item["proposal_id"]),
    ))
    sink_occurrences: Counter[str] = Counter()
    for item in ranked:
        signature = str(item["dynamic_sink_signature"])
        item["queue_wave"] = sink_occurrences[signature]
        sink_occurrences[signature] += 1
    # Exercise every distinct sink once before spending budget on a second
    # lifecycle/state variant of the same sink.
    ranked.sort(key=lambda item: (
        int(item["queue_wave"]),
        -int(item["effective_priority"]),
        -int(item["base_priority"]),
        str(item["family"]),
        str(item["proposal_id"]),
    ))
    targeted = {
        target for item in ranked for target in item["frontier_targets"]
    }
    adapter_backlog = []
    for item in coverage_value.get("security_frontier", ()):
        target_id = str(item["id"])
        if item["covered"] or target_id in targeted:
            continue
        adapter = FRONTIER_ADAPTERS.get(target_id, {})
        adapter_backlog.append({
            "frontier_target": target_id,
            "priority": item["priority"],
            "property": item["property"],
            "reason": "uncovered frontier has no evidence-anchored executable proposal",
            **adapter,
        })
    adapter_backlog.sort(key=lambda item: (-int(item["priority"]),
                                           str(item["frontier_target"])))
    return {
        "schema": "teeweaver-experiment-proposals-v1",
        "meaning": (
            "These are evidence-derived experiments, not vulnerability findings. "
            "A proposal becomes reportable only after target-side acceptance and impact controls."
        ),
        "counts": dict(sorted(Counter(item.family for item in proposals).items())),
        "execution_modes": dict(sorted(Counter(
            item.execution_mode for item in proposals
        ).items())),
        "ranking_policy": (
            "Uncovered security-frontier targets receive +5. Fully covered "
            "targets receive -10. Unbound exploratory plans receive -3. "
            "Adapter-required plans receive a further -1 execution-cost adjustment. "
            "A sink already associated with target crash evidence receives -15 "
            "to reduce same-root-cause rediscovery; this is an overlap warning, "
            "not proof of duplicate root cause. Queue waves exercise each distinct "
            "sink before a second state variant of the same sink."
        ),
        "adapter_backlog": adapter_backlog,
        "proposals": ranked,
    }
