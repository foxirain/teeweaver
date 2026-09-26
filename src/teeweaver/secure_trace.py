from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .events import Event


_PREFIX = re.compile(r"^(?P<level>[A-Z])/(?P<component>[^:]+):(?P<body>.*)$")
_CALLSITE = re.compile(
    r"^(?P<context>.*?)\s*(?P<function>[A-Za-z_][A-Za-z0-9_]*):"
    r"(?P<line>[0-9]+)\s+(?P<message>.*)$"
)
_MARKER = re.compile(r"\bTWTRACE\s+(?P<payload>\{.*\})\s*$")
_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

_LOADING_TS = re.compile(rf"^Loading TS (?P<uuid>{_UUID})$")
_LOOKUP_BINARY = re.compile(
    rf"^Lookup user (?P<kind>TA|SP) ELF (?P<uuid>{_UUID}) "
    r"\((?P<store>[^)]+)\)$"
)
_LOOKUP_RESULT = re.compile(r"^res=(?P<result>0x[0-9a-fA-F]+|[0-9]+)$")
_ELF_MAP = re.compile(
    rf"^ELF \((?P<uuid>{_UUID})\) at (?P<address>0x[0-9a-fA-F]+)$"
)
_MOBJ_LOOKUP = re.compile(
    r"^cookie (?P<cookie>0x[0-9a-fA-F]+) active: refc "
    r"(?P<local>[0-9]+):(?P<global>[0-9]+)$"
)
_RXTX_MAP = re.compile(
    r"^Mapped (?P<kind>tx|rx) (?P<address>0x[0-9a-fA-F]+) "
    r"size (?P<size>0x[0-9a-fA-F]+) @ (?P<physical>0x[0-9a-fA-F]+)$"
)
_SP_MAP_ISSUE = re.compile(
    r"^SP shared map: mobj=(?P<mobj>0x[0-9a-fA-F]+) "
    r"offs=(?P<offset>[0-9]+) pages=(?P<pages>[0-9]+) "
    r"requested_va=(?P<requested>0x[0-9a-fA-F]+|0)$"
)
_SP_MAP_COMPLETE = re.compile(
    r"^SP shared map succeeded: mapped_va=(?P<address>0x[0-9a-fA-F]+)$"
)
_SP_RETRIEVE_RESPONSE = re.compile(
    r"^SP retrieve response: mobj=(?P<mobj>0x[0-9a-fA-F]+) "
    r"offs=(?P<offset>[0-9]+) mapped_va=(?P<address>0x[0-9a-fA-F]+) "
    r"pages=(?P<pages>[0-9]+)$"
)
_SP_RETRIEVE_REJECTED = re.compile(
    r"^SP retrieve rejected: stage=(?P<stage>[0-9]+) ret=(?P<result>-?[0-9]+) "
    r"caller=(?P<caller>0x[0-9a-fA-F]+) "
    r"handle=(?P<handle>0x[0-9a-fA-F]+)$"
)
_SESSION_CLOSE = re.compile(r"^id (?P<session>[0-9]+)$")
_SESSION_REOPEN = re.compile(rf"^Re-open trusted service (?P<uuid>{_UUID})$")
_OPEN_FAILED = re.compile(
    rf"^Failed for TA (?P<uuid>{_UUID})\. Return error "
    r"(?P<result>0x[0-9a-fA-F]+)$"
)
_INIT_FAILED = re.compile(r"^init session failed (?P<result>0x[0-9a-fA-F]+)$")
_INVOKE_FAILED = re.compile(
    r"^Error: (?P<result>(?:0x)?[0-9a-fA-F]+) of (?P<origin>[0-9]+)$"
)
_NOTIFICATION = re.compile(
    r"^(?P<kind>sleep|wake)\s+thread (?P<target>[0-9]+) "
    r"(?P<wait>0x[0-9a-fA-F]+)$"
)
_RPC_FREE = re.compile(r"^freeing cookie (?P<cookie>0x[0-9a-fA-F]+)$")
_FFA_RESURRECT = re.compile(
    r"^cookie (?P<cookie>0x[0-9a-fA-F]+) was resurrected$"
)
_TA_CONTEXT_DESTROY = re.compile(
    r"^Destroy TA ctx \((?P<context>0x[0-9a-fA-F]+)\)$"
)
_TA_PANIC = re.compile(
    r"^tee_user_ta_enter: TA panicked with code (?P<code>0x[0-9a-fA-F]+)$"
)
_SP_CREATE = re.compile(rf"^Loading Secure Partition (?P<uuid>{_UUID})$")
_SP_ENDPOINT = re.compile(r"^endpoint is (?P<endpoint>0x[0-9a-fA-F]+)$")
_SP_START = re.compile(r"^Starting SP: (?P<endpoint>0x[0-9a-fA-F]+)$")
_SP_TEST_RETRIEVE = re.compile(
    r"^retrieve failed: ro=(?P<read_only>[01]) result=(?P<result>-?[0-9]+)$"
)
_LDELF_OPEN_ERROR = re.compile(rf"^sys_open_ta_bin\((?P<uuid>{_UUID})\)$")
_LDELF_FAILED = re.compile(
    r"^ldelf failed with res: (?P<result>0x[0-9a-fA-F]+)$"
)
_LDELF_RUNTIME_MAP = re.compile(
    r"^ldelf load address (?P<address>0x[0-9a-fA-F]+)$"
)
_PSEUDO_TA_LOOKUP = re.compile(rf"^Lookup pseudo TA (?P<uuid>{_UUID})$")
_WATCHDOG_STATE = re.compile(
    r"^WD call_count (?P<calls>[0-9]+), timeout_count (?P<timeouts>[0-9]+)$"
)
_PARTITION_INFO_ERROR = re.compile(
    r"^ffa_partition_info_get\(\): unknown error (?P<result>-?[0-9]+)$"
)
_UUID_VALUE = re.compile(_UUID)
_HEX_VALUE = re.compile(r"0x[0-9a-fA-F]+")
_DECIMAL_VALUE = re.compile(r"(?<![A-Za-z0-9_])-?[0-9]+(?![A-Za-z0-9_])")


@dataclass(frozen=True, slots=True)
class SecureTraceStats:
    lines: int
    parsed_events: int
    structured_events: int
    native_events: int
    ignored_lines: int
    rules: Mapping[str, int]

    def as_dict(self) -> dict[str, Any]:
        return {
            "lines": self.lines,
            "parsed_events": self.parsed_events,
            "structured_events": self.structured_events,
            "native_events": self.native_events,
            "ignored_lines": self.ignored_lines,
            "rules": dict(sorted(self.rules.items())),
        }


@dataclass(frozen=True, slots=True)
class SecureTraceGap:
    """One normalized callsite shape not modeled by the current parser."""

    component: str
    function: str
    template: str
    occurrences: int
    examples: tuple[Mapping[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "function": self.function,
            "template": self.template,
            "occurrences": self.occurrences,
            "examples": [dict(example) for example in self.examples],
        }


def _number(value: str) -> int:
    return int(value, 0)


def _message_template(message: str) -> str:
    value = _UUID_VALUE.sub("<uuid>", message)
    value = _HEX_VALUE.sub("<hex>", value)
    return _DECIMAL_VALUE.sub("<int>", value)


def _result_op(base: str, result: int) -> str:
    return base if result == 0 else f"{base}_error"


def _context_fields(component: str, context: str) -> dict[str, Any]:
    tokens = context.strip().split()
    core = tokens[0] if tokens else "unknown"
    thread = tokens[1] if len(tokens) > 1 else "unknown"
    return {
        "actor": f"secure:{component}:{core}:{thread}",
        # A log prefix exposes an execution core/thread, not the current TA or
        # SP security identity. Do not mislabel CPU migration as a principal
        # handoff. The component is the narrowest defensible principal here.
        "process": f"secure:{component}",
        "thread": f"{component}:{core}:{thread}",
        "secure_core": core,
        "secure_thread": thread,
    }


class _Parser:
    def __init__(self) -> None:
        self.events: list[Event] = []
        self.rules: Counter[str] = Counter()
        self.lines = 0
        self.structured = 0
        self.pending_lookup: dict[str, dict[str, Any]] = {}
        self.lookup_chain_counts: Counter[tuple[str, str]] = Counter()
        self.active_lookup_chains: dict[tuple[str, str], str] = {}
        self.pending_sp_map: dict[str, dict[str, Any]] = {}
        self.sp_map_counts: Counter[str] = Counter()
        self.pending_sessions: dict[str, dict[str, Any]] = {}
        self.session_counts: Counter[str] = Counter()
        self.pending_panics: dict[str, dict[str, Any]] = {}
        self.panic_counts: Counter[str] = Counter()
        self.pending_sp_uuids: list[str] = []
        self.last_ldelf_open_error: dict[str, Any] | None = None

    def _emit(
        self, op: str, *, rule: str, line_number: int, level: str,
        component: str, function: str, context: str, attrs: Mapping[str, Any],
        actor: str | None = None,
    ) -> None:
        context_attrs = _context_fields(component, context)
        event_actor = actor or str(context_attrs.pop("actor"))
        value = {
            "source": "secure-log",
            "order_domain": "secure-log",
            "source_line": line_number,
            "trace_rule": rule,
            "trace_confidence": (
                "explicit-marker" if rule == "structured-marker" else "native-stable"
            ),
            "severity": level,
            "component": component,
            "function": function,
            **context_attrs,
            **dict(attrs),
        }
        self.events.append(Event(len(self.events) + 1, op, event_actor, value))
        self.rules[rule] += 1

    def _structured(
        self, match: re.Match[str], *, line_number: int, level: str,
        component: str, function: str, context: str,
    ) -> bool:
        try:
            value = json.loads(match.group("payload"))
        except json.JSONDecodeError as error:
            raise ValueError(
                f"invalid TWTRACE JSON at secure log line {line_number}: {error}"
            ) from error
        if not isinstance(value, dict) or not isinstance(value.get("op"), str):
            raise ValueError(
                f"TWTRACE line {line_number} must contain an object with string op"
            )
        op = str(value.pop("op"))
        actor = value.pop("actor", None)
        self._emit(
            op, rule="structured-marker", line_number=line_number, level=level,
            component=component, function=function, context=context, attrs=value,
            actor=str(actor) if actor is not None else None,
        )
        self.structured += 1
        return True

    def feed(self, raw_line: str, line_number: int) -> None:
        self.lines += 1
        line = raw_line.rstrip("\r\n")
        prefix = _PREFIX.match(line)
        if not prefix:
            return
        level = prefix.group("level")
        component = prefix.group("component")
        callsite = _CALLSITE.match(prefix.group("body"))
        if not callsite:
            return
        context = callsite.group("context")
        function = callsite.group("function")
        message = callsite.group("message")
        marker = _MARKER.search(message)
        if marker and self._structured(
            marker, line_number=line_number, level=level, component=component,
            function=function, context=context,
        ):
            return

        key = f"{component}:{context.strip()}"
        match = _LOADING_TS.match(message)
        if function == "ldelf" and match:
            uuid = match.group("uuid")
            for chain_key in [
                candidate for candidate in self.active_lookup_chains
                if candidate[1] == uuid
            ]:
                self.active_lookup_chains.pop(chain_key, None)
            self._emit(
                "secure_ts_load_issue", rule="loading-ts",
                line_number=line_number, level=level, component=component,
                function=function, context=context,
                attrs={"object": uuid, "kind": "trusted-service"},
            )
            return
        match = _LOOKUP_BINARY.match(message)
        if function == "ldelf_syscall_open_bin" and match:
            chain_key = (key, match.group("uuid"))
            call = self.active_lookup_chains.get(chain_key)
            if call is None:
                self.lookup_chain_counts[chain_key] += 1
                call = (
                    f"secure-lookup:{key}:{match.group('uuid')}:"
                    f"{self.lookup_chain_counts[chain_key]}"
                )
                self.active_lookup_chains[chain_key] = call
            pending = {
                "object": match.group("uuid"),
                "kind": match.group("kind").lower(),
                "store": match.group("store"),
                "call": call,
            }
            self.pending_lookup[key] = pending
            self._emit(
                "secure_binary_lookup_issue", rule="binary-lookup",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs=pending,
            )
            return
        match = _LOOKUP_RESULT.match(message)
        if function == "ldelf_syscall_open_bin" and match and key in self.pending_lookup:
            result = _number(match.group("result"))
            attrs = {**self.pending_lookup.pop(key), "result": result}
            self._emit(
                _result_op("secure_binary_lookup_complete", result),
                rule="binary-lookup-result", line_number=line_number, level=level,
                component=component, function=function, context=context,
                attrs=attrs,
            )
            if result == 0:
                self.active_lookup_chains.pop((key, str(attrs["object"])), None)
            return
        match = _ELF_MAP.match(message)
        if function == "ldelf" and match:
            self._emit(
                "secure_binary_map", rule="elf-map", line_number=line_number,
                level=level, component=component, function=function,
                context=context, attrs={
                    "object": match.group("uuid"),
                    "address": match.group("address"),
                },
            )
            return
        match = _MOBJ_LOOKUP.match(message)
        if function == "mobj_ffa_get_by_cookie" and match:
            self._emit(
                "secure_mobj_lookup", rule="mobj-cookie", line_number=line_number,
                level=level, component=component, function=function,
                context=context, attrs={
                    "object": match.group("cookie"),
                    "refcount_local": int(match.group("local")),
                    "refcount_global": int(match.group("global")),
                },
            )
            return
        match = _NOTIFICATION.match(message)
        if function == "do_notif" and match:
            kind = match.group("kind")
            self._emit(
                f"secure_thread_{kind}", rule="thread-notification",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs={
                    "object": match.group("wait"),
                    "target_thread": match.group("target"),
                    "kind": kind,
                },
            )
            return
        match = _RPC_FREE.match(message)
        if function == "thread_rpc_free" and match:
            self._emit(
                "secure_rpc_free", rule="rpc-free", line_number=line_number,
                level=level, component=component, function=function,
                context=context, attrs={"object": match.group("cookie")},
            )
            return
        match = _FFA_RESURRECT.match(message)
        if function == "ffa_inactivate" and match:
            self._emit(
                "secure_ffa_resurrect", rule="ffa-resurrect",
                line_number=line_number, level=level, component=component,
                function=function, context=context,
                attrs={"object": match.group("cookie")},
            )
            return
        match = _RXTX_MAP.match(message)
        if function == "spmc_handle_rxtx_map" and match:
            self._emit(
                "secure_rxtx_map", rule="rxtx-map", line_number=line_number,
                level=level, component=component, function=function,
                context=context, attrs={
                    "kind": match.group("kind"),
                    "object": f"{match.group('kind')}:{match.group('address')}",
                    "address": match.group("address"),
                    "physical": match.group("physical"),
                    "size": _number(match.group("size")),
                },
            )
            return
        match = _SP_MAP_ISSUE.match(message)
        if function == "sp_map_shared" and match:
            self.sp_map_counts[key] += 1
            pending = {
                "object": match.group("mobj"),
                "call": f"secure-sp-map:{key}:{self.sp_map_counts[key]}",
            }
            self.pending_sp_map[key] = pending
            self._emit(
                "secure_sp_map_issue", rule="sp-map-issue",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs={
                    **pending,
                    "offset": int(match.group("offset")),
                    "pages": int(match.group("pages")),
                    "requested_address": match.group("requested"),
                },
            )
            return
        match = _SP_MAP_COMPLETE.match(message)
        if function == "sp_map_shared" and match and key in self.pending_sp_map:
            pending = self.pending_sp_map.pop(key)
            self._emit(
                "secure_sp_map_complete", rule="sp-map-complete",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs={
                    **pending,
                    "address": match.group("address"),
                },
            )
            return
        match = _SP_RETRIEVE_RESPONSE.match(message)
        if function == "create_retrieve_response" and match:
            self._emit(
                "secure_sp_retrieve_response", rule="sp-retrieve-response",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs={
                    "object": match.group("mobj"),
                    "offset": int(match.group("offset")),
                    "address": match.group("address"),
                    "pages": int(match.group("pages")),
                },
            )
            return
        match = _SP_RETRIEVE_REJECTED.match(message)
        if function == "ffa_mem_retrieve" and match:
            self._emit(
                "secure_sp_retrieve_error", rule="sp-retrieve-rejected",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs={
                    "object": match.group("handle"),
                    "receiver": match.group("caller"),
                    "stage": int(match.group("stage")),
                    "ioctl_result": int(match.group("result")),
                },
            )
            return
        match = _SESSION_CLOSE.match(message)
        if function == "tee_ta_close_session" and match:
            self.session_counts[key] += 1
            pending = {
                "session": match.group("session"),
                "call": f"secure-session-close:{key}:{self.session_counts[key]}",
            }
            self.pending_sessions[key] = pending
            self._emit(
                "secure_session_close_issue", rule="session-close",
                line_number=line_number, level=level, component=component,
                function=function, context=context,
                attrs=pending,
            )
            return
        if (function == "tee_ta_close_session" and message == "Destroy session"
                and key in self.pending_sessions):
            self._emit(
                "secure_session_destroy_complete", rule="session-destroy",
                line_number=line_number, level=level, component=component,
                function=function, context=context,
                attrs=self.pending_sessions.pop(key),
            )
            return
        match = _SESSION_REOPEN.match(message)
        if function == "tee_ta_init_session_with_context" and match:
            self._emit(
                "secure_session_reopen", rule="session-reopen",
                line_number=line_number, level=level, component=component,
                function=function, context=context,
                attrs={"object": match.group("uuid")},
            )
            return
        match = _OPEN_FAILED.match(message)
        if function == "tee_ta_open_session" and match:
            self._emit(
                "secure_session_open_error", rule="session-open-error",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs={
                    "object": match.group("uuid"),
                    "result": _number(match.group("result")),
                },
            )
            return
        match = _INIT_FAILED.match(message)
        if function == "tee_ta_open_session" and match:
            self._emit(
                "secure_session_init_error", rule="session-init-error",
                line_number=line_number, level=level, component=component,
                function=function, context=context,
                attrs={"result": _number(match.group("result"))},
            )
            return
        match = _INVOKE_FAILED.match(message)
        if function == "tee_ta_invoke_command" and match:
            self._emit(
                "secure_command_error", rule="command-error",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs={
                    "result": _number(
                        match.group("result") if match.group("result").startswith("0x")
                        else f"0x{match.group('result')}"
                    ),
                    "origin": int(match.group("origin")),
                },
            )
            return
        if function == "ree_fs_open_primitive" and message == "Remove corrupt file":
            self._emit(
                "secure_storage_corrupt_remove", rule="ree-fs-corrupt-remove",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs={"kind": "ree-fs"},
            )
            return
        match = _TA_CONTEXT_DESTROY.match(message)
        if function == "destroy_context" and match:
            self._emit(
                "secure_ta_context_destroy", rule="ta-context-destroy",
                line_number=line_number, level=level, component=component,
                function=function, context=context,
                attrs={"context": match.group("context")},
            )
            return
        match = _TA_PANIC.match(message)
        if function == "user_ta_enter" and match:
            self.panic_counts[key] += 1
            pending = {
                "call": f"secure-ta-panic:{key}:{self.panic_counts[key]}",
                "panic_code": _number(match.group("code")),
            }
            self.pending_panics[key] = pending
            self._emit(
                "secure_ta_panic_issue", rule="ta-panic",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs=pending,
            )
            return
        if (function == "maybe_release_ta_ctx"
                and message == "Releasing panicked TA ctx"
                and key in self.pending_panics):
            self._emit(
                "secure_ta_panic_release_complete", rule="ta-panic-release",
                line_number=line_number, level=level, component=component,
                function=function, context=context,
                attrs=self.pending_panics.pop(key),
            )
            return
        match = _SP_CREATE.match(message)
        if function == "sp_create_session" and match:
            uuid = match.group("uuid")
            self.pending_sp_uuids.append(uuid)
            self._emit(
                "secure_sp_create", rule="sp-create", line_number=line_number,
                level=level, component=component, function=function,
                context=context, attrs={"object": uuid, "kind": "sp"},
            )
            return
        match = _SP_ENDPOINT.match(message)
        if function == "sp_init_uuid" and match:
            attrs: dict[str, Any] = {
                "endpoint": match.group("endpoint"),
                "target": match.group("endpoint"),
                "kind": "sp",
            }
            if self.pending_sp_uuids:
                attrs["object"] = self.pending_sp_uuids.pop(0)
            self._emit(
                "secure_sp_endpoint_bind", rule="sp-endpoint-bind",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs=attrs,
            )
            return
        match = _SP_START.match(message)
        if function == "sp_init_all" and match:
            endpoint = match.group("endpoint")
            self._emit(
                "secure_sp_start", rule="sp-start", line_number=line_number,
                level=level, component=component, function=function,
                context=context, attrs={
                    "endpoint": endpoint, "target": endpoint, "kind": "sp",
                },
            )
            return
        match = _SP_TEST_RETRIEVE.match(message)
        if function == "test_mem_retrieve" and match:
            self._emit(
                "secure_sp_test_retrieve_error", rule="sp-test-retrieve-error",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs={
                    "read_only": bool(int(match.group("read_only"))),
                    "result": int(match.group("result")),
                },
            )
            return
        match = _LDELF_OPEN_ERROR.match(message)
        if function == "init_elf" and match:
            self.last_ldelf_open_error = {
                "object": match.group("uuid"),
                "call": f"secure-ldelf-open:{line_number}",
                "trace_confidence": "native-adjacent-correlation",
            }
            self._emit(
                "secure_ldelf_open_error", rule="ldelf-open-error",
                line_number=line_number, level=level, component=component,
                function=function, context=context,
                attrs=self.last_ldelf_open_error,
            )
            return
        match = _LDELF_FAILED.match(message)
        if function == "ldelf_init_with_ldelf" and match:
            attrs = {
                "result": _number(match.group("result")),
                "trace_confidence": "native-stable",
            }
            if self.last_ldelf_open_error is not None:
                attrs.update(self.last_ldelf_open_error)
                self.last_ldelf_open_error = None
            self._emit(
                "secure_ldelf_init_error", rule="ldelf-init-error",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs=attrs,
            )
            return
        match = _LDELF_RUNTIME_MAP.match(message)
        if function == "ldelf_load_ldelf" and match:
            self._emit(
                "secure_ldelf_runtime_map", rule="ldelf-runtime-map",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs={
                    "address": match.group("address"), "kind": "ldelf",
                },
            )
            return
        match = _PSEUDO_TA_LOOKUP.match(message)
        if function == "tee_ta_init_pseudo_ta_session" and match:
            self._emit(
                "secure_pseudo_ta_lookup", rule="pseudo-ta-lookup",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs={
                    "object": match.group("uuid"), "kind": "pseudo-ta",
                },
            )
            return
        match = _WATCHDOG_STATE.match(message)
        if function == "test_wd_callback" and match:
            self._emit(
                "secure_watchdog_state", rule="watchdog-state",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs={
                    "call_count": int(match.group("calls")),
                    "timeout_count": int(match.group("timeouts")),
                },
            )
            return
        if function == "wd_ndrv_yielding_cb" and message == "Clearing pending":
            self._emit(
                "secure_watchdog_pending_clear", rule="watchdog-clear",
                line_number=line_number, level=level, component=component,
                function=function, context=context, attrs={},
            )
            return
        match = _PARTITION_INFO_ERROR.match(message)
        if function == "ffa_partition_info_get_process" and match:
            self._emit(
                "secure_sp_partition_info_error", rule="sp-partition-info-error",
                line_number=line_number, level=level, component=component,
                function=function, context=context,
                attrs={"result": int(match.group("result"))},
            )

    def finish(self) -> tuple[list[Event], SecureTraceStats]:
        parsed = len(self.events)
        stats = SecureTraceStats(
            lines=self.lines,
            parsed_events=parsed,
            structured_events=self.structured,
            native_events=parsed - self.structured,
            ignored_lines=self.lines - parsed,
            rules=dict(self.rules),
        )
        return self.events, stats


def parse_secure_lines(lines: Iterable[str]) -> tuple[list[Event], SecureTraceStats]:
    parser = _Parser()
    for line_number, line in enumerate(lines, 1):
        parser.feed(line, line_number)
    return parser.finish()


def read_secure_log(path: str | Path) -> tuple[list[Event], SecureTraceStats]:
    with Path(path).open("r", encoding="utf-8", errors="replace") as stream:
        return parse_secure_lines(stream)


def profile_secure_gaps(
    paths: Iterable[str | Path], *, limit: int = 256,
    minimum_count: int = 1,
) -> dict[str, Any]:
    """Rank normalized OP-TEE callsite records the parser does not model."""

    if limit < 1:
        raise ValueError("limit must be positive")
    if minimum_count < 1:
        raise ValueError("minimum_count must be positive")
    counts: Counter[tuple[str, str, str]] = Counter()
    examples: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    total_lines = 0
    callsite_lines = 0
    parsed_lines = 0
    path_count = 0
    rules: Counter[str] = Counter()
    for raw_path in paths:
        path = Path(raw_path)
        parser = _Parser()
        path_count += 1
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line_number, raw_line in enumerate(stream, 1):
                total_lines += 1
                line = raw_line.rstrip("\r\n")
                prefix = _PREFIX.match(line)
                callsite = (
                    _CALLSITE.match(prefix.group("body")) if prefix else None
                )
                if callsite:
                    callsite_lines += 1
                before = len(parser.events)
                parser.feed(raw_line, line_number)
                if len(parser.events) != before:
                    parsed_lines += 1
                    continue
                if not prefix or not callsite:
                    continue
                key = (
                    prefix.group("component"), callsite.group("function"),
                    _message_template(callsite.group("message")),
                )
                counts[key] += 1
                sample = examples.setdefault(key, [])
                if len(sample) < 3:
                    sample.append({
                        "path": str(path),
                        "line": line_number,
                        "level": prefix.group("level"),
                        "message": callsite.group("message"),
                    })
        _, stats = parser.finish()
        rules.update(stats.rules)
    selected = [
        SecureTraceGap(component, function, template, count,
                       tuple(examples[(component, function, template)]))
        for (component, function, template), count in counts.items()
        if count >= minimum_count
    ]
    selected.sort(
        key=lambda gap: (-gap.occurrences, gap.component, gap.function,
                         gap.template)
    )
    selected = selected[:limit]
    return {
        "schema": "teeweaver-secure-trace-gaps-v1",
        "meaning": (
            "Unmodeled normalized log shapes ranked by frequency. Frequency is "
            "not security impact; use these records to select observation work."
        ),
        "paths": path_count,
        "lines": total_lines,
        "callsite_lines": callsite_lines,
        "parsed_lines": parsed_lines,
        "unmodeled_callsite_lines": sum(counts.values()),
        "parsed_callsite_fraction": round(
            parsed_lines / max(1, callsite_lines), 4
        ),
        "active_rules": dict(sorted(rules.items())),
        "returned_gaps": len(selected),
        "gaps": [gap.as_dict() for gap in selected],
    }
