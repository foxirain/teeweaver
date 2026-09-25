from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class Event:
    """One externally observable transition in a cross-world history."""

    seq: int
    op: str
    actor: str
    attrs: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], default_seq: int) -> "Event":
        reserved = {"seq", "op", "actor"}
        return cls(
            seq=int(value.get("seq", default_seq)),
            op=str(value["op"]),
            actor=str(value.get("actor", "unknown")),
            attrs={k: v for k, v in value.items() if k not in reserved},
        )

    def as_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "op": self.op, "actor": self.actor, **self.attrs}

    def get(self, key: str, default: Any = None) -> Any:
        return self.attrs.get(key, default)

