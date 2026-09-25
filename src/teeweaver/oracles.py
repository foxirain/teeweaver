from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable

from .events import Event


@dataclass(frozen=True, slots=True)
class Violation:
    code: str
    seq: int
    message: str
    evidence: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Stimulus:
    code: str
    seq: int
    message: str
    evidence: dict[str, Any]


class OracleEngine:
    """Checks security invariants over an event history.

    These checks deliberately avoid relying on a crash. They model identity,
    generation, lifetime, authentication-to-use consistency, failure atomicity,
    and reset freshness.
    """

    def __init__(self) -> None:
        self.pending_rpc: dict[str, dict[str, Any]] = {}
        self.delivered_rpc: dict[str, dict[str, Any]] = {}
        self.resources: dict[str, dict[str, Any]] = {}
        self.ffa_resources: dict[str, dict[str, Any]] = {}
        self.ffa_bindings: dict[str, tuple[str, int]] = {}
        self.verified: dict[tuple[str, int], str] = {}
        self.failed_ops: set[str] = set()
        self.live_operations: dict[str, dict[str, Any]] = {}
        self.epoch = 0
        self.acked_storage: dict[str, tuple[int, str]] = {}
        self.violations: list[Violation] = []
        self.stimuli: list[Stimulus] = []
        self.semantic_states: set[tuple[Any, ...]] = set()

    def _violate(self, code: str, event: Event, message: str, **evidence: Any) -> None:
        self.violations.append(Violation(code, event.seq, message, evidence))

    def _stimulus(self, code: str, event: Event, message: str, **evidence: Any) -> None:
        self.stimuli.append(Stimulus(code, event.seq, message, evidence))

    @staticmethod
    def _identity(event: Event) -> dict[str, Any]:
        keys = ("func", "session", "object", "generation", "epoch")
        return {key: event.get(key) for key in keys if event.get(key) is not None}

    def _capture_coverage(self, event: Event) -> None:
        # Coverage must be stable under identity renaming. Raw request IDs,
        # shared-memory IDs, thread IDs, and owner strings vary across otherwise
        # equivalent executions and would turn ordinary scheduling noise into
        # false semantic novelty.
        resource_shape = tuple(
            sorted(
                Counter(
                    # Absolute generation numbers are execution counters, not
                    # semantic identities. Coverage records whether an object
                    # is a reused generation; the oracle still compares exact
                    # generations when checking a use/release transition.
                    (state["generation"] > 1, state["live"])
                    for state in self.resources.values()
                    if state["live"]
                ).items()
            )
        )
        rpc_shape = tuple(
            sorted(
                Counter(
                    (
                        pending.get("func"),
                        pending.get("session") is not None,
                        (
                            pending.get("generation") is not None
                            and int(pending["generation"]) > 1
                        ),
                    )
                    for pending in self.pending_rpc.values()
                ).items()
            )
        )
        delivered_shape = tuple(
            sorted(
                Counter(
                    (
                        delivered.get("func"),
                        delivered.get("session") is not None,
                        (
                            delivered.get("generation") is not None
                            and int(delivered["generation"]) > 1
                        ),
                        delivered.get("content_from")
                        == request,
                    )
                    for request, delivered in self.delivered_rpc.items()
                ).items()
            )
        )
        operation_shape = tuple(
            sorted(
                Counter(
                    (
                        state.get("command"),
                        state.get("cancelled", False),
                    )
                    for state in self.live_operations.values()
                ).items()
            )
        )
        ffa_shape = tuple(
            sorted(
                Counter(
                    (
                        state["generation"] > 1,
                        state["live"],
                        sum(state["receivers"].values()),
                        len(
                            [
                                count
                                for count in state["receivers"].values()
                                if count > 0
                            ]
                        ),
                    )
                    for state in self.ffa_resources.values()
                ).items()
            )
        )
        self.semantic_states.add(
            (
                self.epoch,
                event.op,
                event.get("fault"),
                rpc_shape,
                delivered_shape,
                resource_shape,
                operation_shape,
                ffa_shape,
            )
        )

    def process(self, event: Event) -> None:
        op = event.op

        if op == "rpc_issue":
            request = str(event.get("request"))
            if request in self.pending_rpc:
                self._violate(
                    "RPC_ID_REUSE",
                    event,
                    "a live RPC identity was reused",
                    request=request,
                )
            self.pending_rpc[request] = {
                "actor": event.actor,
                **self._identity(event),
            }

        elif op == "rpc_reply":
            request = str(event.get("request"))
            ioctl_result = int(event.get("ioctl_result", 0))
            if ioctl_result < 0:
                self._stimulus(
                    "RPC_REPLY_REJECTED_STIMULUS",
                    event,
                    "the Linux TEE driver rejected the attempted RPC response",
                    request=request,
                    ioctl_result=ioctl_result,
                )
                self._capture_coverage(event)
                return

            fault = str(event.get("fault", ""))
            if fault == "flip-memref":
                self._stimulus(
                    "RPC_MEMREF_MUTATION_STIMULUS",
                    event,
                    "the REE changed a mapped RPC response byte before returning it",
                    request=request,
                    func=event.get("func"),
                    param=event.get("fault_param"),
                    offset=event.get("fault_offset"),
                    before=event.get("fault_before"),
                    after=event.get("fault_after"),
                )
            elif fault == "force-ret":
                self._stimulus(
                    "RPC_RETURN_CODE_STIMULUS",
                    event,
                    "the REE replaced the RPC return code",
                    request=request,
                    func=event.get("func"),
                )
            elif fault == "delay":
                self._stimulus(
                    "RPC_DELAY_STIMULUS",
                    event,
                    "the REE delayed an RPC response across a scheduling boundary",
                    request=request,
                    func=event.get("func"),
                )

            pending = self.pending_rpc.pop(request, None)
            if pending is None:
                self._stimulus(
                    "RPC_ORPHAN_REPLY_STIMULUS",
                    event,
                    "the REE attempted to reply to a non-live request",
                    request=request,
                )
            else:
                claimed = str(event.get("claims_request", request))
                self.delivered_rpc[request] = {
                    **pending,
                    "content_from": claimed,
                    "reply_identity": self._identity(event),
                }
                if str(claimed) != request:
                    self._stimulus(
                        "RPC_CROSS_BIND_STIMULUS",
                        event,
                        "the REE delivered response content under another live request ID",
                        delivered_to=request,
                        content_from=claimed,
                    )
                for key, expected in pending.items():
                    if key == "actor" or expected is None or event.get(key) is None:
                        continue
                    if event.get(key) != expected:
                        self._stimulus(
                            "RPC_CONTEXT_MISMATCH_STIMULUS",
                            event,
                            f"the REE changed RPC response field {key}",
                            request=request,
                            field=key,
                            expected=expected,
                            observed=event.get(key),
                        )

        elif op == "rpc_accept":
            request = str(event.get("request"))
            delivered = self.delivered_rpc.pop(request, None)
            if delivered is None:
                self._violate(
                    "RPC_ACCEPT_WITHOUT_REPLY",
                    event,
                    "Secure World accepted an RPC result with no recorded response",
                    request=request,
                )
            else:
                content_from = str(event.get("content_from", delivered["content_from"]))
                if content_from != request:
                    self._violate(
                        "RPC_CROSS_BIND_ACCEPTED",
                        event,
                        "Secure World consumed response content from another request",
                        accepted_by=request,
                        content_from=content_from,
                    )
                for key, expected in delivered.items():
                    if key in {"actor", "content_from", "reply_identity"}:
                        continue
                    if expected is None or event.get(key) is None:
                        continue
                    if event.get(key) != expected:
                        self._violate(
                            "RPC_WRONG_CONTEXT_ACCEPTED",
                            event,
                            f"Secure World accepted an RPC result under the wrong {key}",
                            request=request,
                            field=key,
                            expected=expected,
                            observed=event.get(key),
                        )

        elif op == "shm_register":
            obj = str(event.get("object"))
            generation = int(event.get("generation", 0))
            old = self.resources.get(obj)
            if old and old["live"]:
                self._violate(
                    "SHM_DOUBLE_REGISTER",
                    event,
                    "a live shared-memory identity was registered again",
                    object=obj,
                    old_generation=old["generation"],
                    new_generation=generation,
                )
            if old and generation <= old["generation"]:
                self._violate(
                    "SHM_GENERATION_REGRESSION",
                    event,
                    "shared-memory generation did not advance on reuse",
                    object=obj,
                    old_generation=old["generation"],
                    new_generation=generation,
                )
            self.resources[obj] = {
                "generation": generation,
                "owner": event.get("owner", event.actor),
                "live": True,
            }

        elif op == "shm_release":
            obj = str(event.get("object"))
            generation = int(event.get("generation", -1))
            state = self.resources.get(obj)
            if not state or not state["live"] or state["generation"] != generation:
                self._violate(
                    "SHM_INVALID_RELEASE",
                    event,
                    "release did not refer to the live resource generation",
                    object=obj,
                    generation=generation,
                )
            elif state:
                state["live"] = False

        elif op == "shm_use":
            obj = str(event.get("object"))
            generation = int(event.get("generation", -1))
            state = self.resources.get(obj)
            if not state or not state["live"] or state["generation"] != generation:
                self._violate(
                    "SHM_STALE_USE",
                    event,
                    "shared memory was used outside its live generation",
                    object=obj,
                    generation=generation,
                    current=state,
                )
            elif (
                not bool(event.get("shared", False))
                and event.get("owner") is not None
                and event.get("owner") != state.get("owner")
            ):
                self._violate(
                    "SHM_OWNER_MISMATCH",
                    event,
                    "shared memory was consumed by a different owner",
                    object=obj,
                    expected_owner=state.get("owner"),
                    observed_owner=event.get("owner"),
                )

        elif op == "ffa_share":
            obj = str(event.get("object"))
            generation = int(event.get("generation", 0))
            old = self.ffa_resources.get(obj)
            if old and old["live"]:
                self._violate(
                    "FFA_LIVE_HANDLE_REUSE",
                    event,
                    "FF-A returned a handle that was already live",
                    object=obj,
                    old_generation=old["generation"],
                    new_generation=generation,
                )
            if old and generation <= old["generation"]:
                self._violate(
                    "FFA_GENERATION_REGRESSION",
                    event,
                    "an FF-A handle reuse did not advance its generation",
                    object=obj,
                    old_generation=old["generation"],
                    new_generation=generation,
                )
            self.ffa_resources[obj] = {
                "generation": generation,
                "owner": event.get("owner", event.actor),
                "receiver": str(event.get("receiver")),
                "live": True,
                "receivers": {},
            }

        elif op == "ffa_retrieve":
            obj = str(event.get("object"))
            generation = int(event.get("generation", -1))
            receiver = str(event.get("receiver"))
            state = self.ffa_resources.get(obj)
            if not state or not state["live"] or state["generation"] != generation:
                self._violate(
                    "FFA_STALE_RETRIEVE_ACCEPTED",
                    event,
                    "an SP successfully retrieved a non-live FF-A handle generation",
                    object=obj,
                    generation=generation,
                    current=state,
                    receiver=receiver,
                )
            else:
                if receiver != state["receiver"]:
                    self._violate(
                        "FFA_WRONG_RECEIVER_RETRIEVE_ACCEPTED",
                        event,
                        "an FF-A handle was retrieved by a receiver outside the share",
                        object=obj,
                        expected_receiver=state["receiver"],
                        observed_receiver=receiver,
                    )
                state["receivers"][receiver] = (
                    state["receivers"].get(receiver, 0) + 1
                )
            self.ffa_bindings[receiver] = (obj, generation)

        elif op == "ffa_relinquish":
            obj = str(event.get("object"))
            generation = int(event.get("generation", -1))
            receiver = str(event.get("receiver"))
            state = self.ffa_resources.get(obj)
            count = state["receivers"].get(receiver, 0) if state else 0
            if (
                not state
                or not state["live"]
                or state["generation"] != generation
                or count < 1
            ):
                self._violate(
                    "FFA_INVALID_RELINQUISH_ACCEPTED",
                    event,
                    "the SPMC accepted a relinquish without a matching live retrieve",
                    object=obj,
                    generation=generation,
                    receiver=receiver,
                    current=state,
                )
            else:
                state["receivers"][receiver] = count - 1
                if count == 1 and self.ffa_bindings.get(receiver) == (
                    obj,
                    generation,
                ):
                    self.ffa_bindings.pop(receiver, None)

        elif op == "ffa_reclaim":
            obj = str(event.get("object"))
            generation = int(event.get("generation", -1))
            state = self.ffa_resources.get(obj)
            if not state or not state["live"] or state["generation"] != generation:
                self._violate(
                    "FFA_INVALID_RECLAIM_ACCEPTED",
                    event,
                    "Normal World successfully reclaimed a non-live FF-A generation",
                    object=obj,
                    generation=generation,
                    current=state,
                )
            else:
                live_receivers = {
                    receiver: count
                    for receiver, count in state["receivers"].items()
                    if count > 0
                }
                if live_receivers:
                    self._violate(
                        "FFA_RECLAIM_WITH_LIVE_RECEIVER",
                        event,
                        "Normal World reclaimed memory while an SP retained access",
                        object=obj,
                        generation=generation,
                        live_receivers=live_receivers,
                    )
                state["live"] = False

        elif op == "ffa_access":
            receiver = str(event.get("receiver"))
            obj_value = event.get("object")
            generation_value = event.get("generation")
            binding = self.ffa_bindings.get(receiver)
            if obj_value is None and binding:
                obj_value, generation_value = binding
            obj = str(obj_value)
            generation = int(generation_value if generation_value is not None else -1)
            state = self.ffa_resources.get(obj)
            count = state["receivers"].get(receiver, 0) if state else 0
            if not state or not state["live"] or state["generation"] != generation:
                self._violate(
                    "FFA_ACCESS_AFTER_RECLAIM",
                    event,
                    "an SP successfully accessed a non-live FF-A handle generation",
                    object=obj,
                    generation=generation,
                    receiver=receiver,
                    access=event.get("access"),
                    current=state,
                )
            elif count < 1:
                self._violate(
                    "FFA_ACCESS_WITHOUT_RETRIEVE",
                    event,
                    "an SP successfully accessed memory without a live retrieve",
                    object=obj,
                    generation=generation,
                    receiver=receiver,
                    access=event.get("access"),
                )

        elif op == "ffa_fault":
            self._stimulus(
                "FFA_ADVERSARIAL_TRANSITION_STIMULUS",
                event,
                "Normal World changed the FF-A transition history",
                fault=event.get("fault"),
                target=event.get("target"),
                occurrence=event.get("occurrence"),
            )

        elif op == "object_verify":
            key = (str(event.get("object")), int(event.get("generation", 0)))
            self.verified[key] = str(event.get("digest"))

        elif op == "object_consume":
            key = (str(event.get("object")), int(event.get("generation", 0)))
            expected = self.verified.get(key)
            observed = str(event.get("digest"))
            if expected is None:
                self._violate(
                    "USE_WITHOUT_VERIFICATION",
                    event,
                    "an object was consumed without verification in this generation",
                    object=key[0],
                    generation=key[1],
                )
            elif observed != expected:
                self._violate(
                    "VERIFY_USE_DRIFT",
                    event,
                    "consumed bytes differ from authenticated bytes",
                    object=key[0],
                    generation=key[1],
                    verified_digest=expected,
                    consumed_digest=observed,
                )

        elif op == "operation_issue":
            operation = str(event.get("operation"))
            self.live_operations[operation] = {
                "session": event.get("session"),
                "command": event.get("command"),
                "cancelled": False,
            }

        elif op == "operation_cancel":
            operation = str(event.get("operation"))
            self.failed_ops.add(operation)
            state = self.live_operations.get(operation)
            if state:
                state["cancelled"] = True
            else:
                self._stimulus(
                    "CANCEL_UNKNOWN_OPERATION_STIMULUS",
                    event,
                    "the client requested cancellation outside a recorded live operation",
                    operation=operation,
                )

        elif op == "operation_fail":
            operation = str(event.get("operation"))
            self.failed_ops.add(operation)
            self.live_operations.pop(operation, None)

        elif op == "operation_complete":
            operation = str(event.get("operation"))
            state = self.live_operations.pop(operation, None)
            if state and state.get("cancelled"):
                self._stimulus(
                    "CANCELLED_OPERATION_COMPLETED_STIMULUS",
                    event,
                    "an operation completed successfully after a cancellation request",
                    operation=operation,
                    command=state.get("command"),
                )

        elif op == "side_effect":
            operation = str(event.get("operation"))
            if operation in self.failed_ops:
                self._violate(
                    "FAILED_OPERATION_SIDE_EFFECT",
                    event,
                    "a failed or cancelled operation produced a later side effect",
                    operation=operation,
                    effect=event.get("effect"),
                )

        elif op == "storage_ack":
            key = str(event.get("key"))
            self.acked_storage[key] = (self.epoch, str(event.get("digest")))

        elif op == "reset":
            self.epoch += 1
            self.pending_rpc.clear()
            self.delivered_rpc.clear()
            for state in self.resources.values():
                state["live"] = False
            for state in self.ffa_resources.values():
                state["live"] = False
            self.ffa_bindings.clear()

        elif op == "storage_observe":
            key = str(event.get("key"))
            acknowledged = self.acked_storage.get(key)
            if acknowledged and str(event.get("digest")) != acknowledged[1]:
                self._violate(
                    "PERSISTENCE_ROLLBACK",
                    event,
                    "an acknowledged persistent value rolled back after a reset",
                    key=key,
                    acknowledged_epoch=acknowledged[0],
                    acknowledged_digest=acknowledged[1],
                    observed_epoch=self.epoch,
                    observed_digest=event.get("digest"),
                )

        self._capture_coverage(event)

    def check(self, events: Iterable[Event]) -> list[Violation]:
        for event in events:
            self.process(event)
        return self.violations

    def semantic_state_ids(self) -> list[str]:
        """Return stable, compact identifiers for the reached semantic states."""

        return sorted(
            hashlib.sha256(repr(state).encode("utf-8")).hexdigest()[:16]
            for state in self.semantic_states
        )


def check(events: Iterable[Event]) -> tuple[list[Violation], list[Stimulus], int]:
    engine = OracleEngine()
    return engine.check(events), engine.stimuli, len(engine.semantic_states)


def evaluate(
    events: Iterable[Event],
) -> tuple[list[Violation], list[Stimulus], list[str]]:
    engine = OracleEngine()
    violations = engine.check(events)
    return violations, engine.stimuli, engine.semantic_state_ids()
