from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping


REQUIRED_GATES = (
    "supported_configuration",
    "stock_target_reproduction",
    "normal_world_attacker",
    "secure_world_security_impact",
    "negative_control",
    "observer_effect_control",
    "minimized_reproducer",
    "duplicate_triage",
)


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    stage: str
    promotable: bool
    satisfied: tuple[str, ...]
    missing: tuple[str, ...]
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def decide_promotion(
    summary: Mapping[str, Any], evidence: Mapping[str, Any]
) -> PromotionDecision:
    """Apply the disclosure gate without inferring exploitability from a symptom."""

    violations = tuple(summary.get("violations", ()))
    run_error = summary.get("run_error")
    satisfied = tuple(name for name in REQUIRED_GATES if evidence.get(name) is True)
    missing = tuple(name for name in REQUIRED_GATES if evidence.get(name) is not True)

    if run_error:
        return PromotionDecision(
            "infrastructure-failure",
            False,
            satisfied,
            missing,
            (f"runner reported {run_error}",),
        )
    if not violations:
        return PromotionDecision(
            "not-a-candidate",
            False,
            satisfied,
            missing,
            ("no accepted security-invariant violation was recorded",),
        )
    if missing:
        return PromotionDecision(
            "hold-for-validation",
            False,
            satisfied,
            missing,
            ("an oracle violation exists, but reportability evidence is incomplete",),
        )
    return PromotionDecision(
        "reportable-candidate",
        True,
        satisfied,
        (),
        (
            "all mechanical reportability gates are satisfied; severity still "
            "requires manual impact and attack-precondition calibration",
        ),
    )
