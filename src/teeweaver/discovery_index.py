from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

from .discovery import (
    FAMILY_WEIGHTS,
    RELATIONAL_FAMILIES,
    TEMPORAL_FAMILIES,
    RunProfile,
)


FAMILY_NOVELTY_CAPS = {
    "cardinality": 0.5,
    "operation": 2.0,
    "outcome": 2.0,
    "semantic-state": 1.5,
    "byte-continuity": 12.0,
    "cross-principal": 10.0,
    "epoch-continuity": 12.0,
    "failure-followup": 12.0,
    "identity-alias": 10.0,
    "identity-binding": 12.0,
    "incomplete-transition": 12.0,
    "lifecycle": 8.0,
    "order": 6.0,
    "overlap": 10.0,
    "principal-handoff": 11.0,
    "progress-cycle": 6.0,
    "reentrancy": 12.0,
    "reset-epoch": 10.0,
    "retry-transition": 11.0,
    "state-alias": 8.0,
    "value-transition": 10.0,
}


def _signature(profile: RunProfile) -> str:
    payload = json.dumps(
        sorted(profile.feature_ids), separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def _structural_features(
    features: set[str], families: Mapping[str, str],
) -> set[str]:
    return {
        feature for feature in features
        if families.get(feature) != "outcome"
    }


@dataclass(frozen=True, slots=True)
class IndexDecision:
    run: str
    disposition: str
    priority_score: float
    signature: str
    new_features: tuple[str, ...]
    rare_features: tuple[str, ...]
    new_relational_families: tuple[str, ...]
    nearest_retained_run: str | None
    nearest_similarity: float | None
    contrast_run: str | None
    contrast_kind: str | None
    reasons: tuple[str, ...]

    @property
    def retain(self) -> bool:
        return self.disposition == "retain"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class NoveltyIndex:
    """Incremental semantic corpus memory for long-running campaigns.

    The index decides whether a history adds discovery coverage. It never
    decides whether the history is a vulnerability.
    """

    SCHEMA = "teeweaver-novelty-index-v1"

    def __init__(self) -> None:
        self.observed_runs = 0
        self.feature_support: Counter[str] = Counter()
        self.family_support: Counter[str] = Counter()
        self.seen_runs: dict[str, dict[str, str]] = {}
        self.retained_profiles: dict[str, dict[str, Any]] = {}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "NoveltyIndex":
        if value.get("schema") != cls.SCHEMA:
            raise ValueError("unsupported novelty index schema")
        index = cls()
        index.observed_runs = int(value.get("observed_runs", 0))
        index.feature_support.update({
            str(key): int(count)
            for key, count in dict(value.get("feature_support", {})).items()
        })
        index.family_support.update({
            str(key): int(count)
            for key, count in dict(value.get("family_support", {})).items()
        })
        seen = value.get("seen_runs", {})
        retained = value.get("retained_profiles", {})
        if not isinstance(seen, Mapping) or not isinstance(retained, Mapping):
            raise ValueError("novelty index run maps must be objects")
        index.seen_runs = {
            str(label): {str(key): str(item) for key, item in dict(record).items()}
            for label, record in seen.items() if isinstance(record, Mapping)
        }
        index.retained_profiles = {
            str(label): dict(record)
            for label, record in retained.items() if isinstance(record, Mapping)
        }
        return index

    def _nearest(self, profile: RunProfile) -> tuple[str | None, float | None]:
        if not self.retained_profiles:
            return None, None
        features = _structural_features(
            set(profile.feature_ids), profile.feature_families
        )
        label, record = max(
            self.retained_profiles.items(),
            key=lambda item: (
                _jaccard(
                    features,
                    _structural_features(
                        set(item[1].get("feature_ids", ())),
                        dict(item[1].get("feature_families", {})),
                    ),
                ),
                item[0],
            ),
        )
        peer_features = _structural_features(
            set(record.get("feature_ids", ())),
            dict(record.get("feature_families", {})),
        )
        return label, round(
            _jaccard(features, peer_features), 4
        )

    def _contrast(self, profile: RunProfile) -> tuple[str | None, str | None]:
        features = _structural_features(
            set(profile.feature_ids), profile.feature_families
        )
        candidates = []
        for label, record in self.retained_profiles.items():
            if str(record.get("group")) != profile.group:
                continue
            peer_families = {
                str(key): str(value)
                for key, value in dict(record.get("feature_families", {})).items()
            }
            peer_features = _structural_features(
                set(record.get("feature_ids", ())), peer_families
            )
            similarity = _jaccard(features, peer_features)
            core = {
                feature for feature in features
                if profile.feature_families.get(feature) not in TEMPORAL_FAMILIES
            }
            peer_core = {
                feature for feature in peer_features
                if peer_families.get(feature) not in TEMPORAL_FAMILIES
            }
            peer_outcome = str(record.get("outcome"))
            unique = features ^ peer_features
            strong_unique = {
                feature for feature in unique
                if profile.feature_families.get(
                    feature, peer_families.get(feature)
                ) in {
                    "byte-continuity", "cross-principal", "failure-followup",
                    "incomplete-transition", "overlap", "reset-epoch",
                    "identity-binding", "value-transition", "epoch-continuity",
                    "identity-alias", "principal-handoff", "progress-cycle",
                    "reentrancy", "retry-transition",
                }
            }
            if peer_outcome != profile.outcome and features == peer_features:
                kind = "same-history-different-outcome"
                strength = 5
            elif peer_outcome != profile.outcome and core == peer_core:
                kind = "same-core-different-schedule-outcome"
                strength = 4
            elif peer_outcome != profile.outcome and similarity >= 0.65:
                kind = "different-outcome-nearby-history"
                strength = 3
            elif peer_outcome == profile.outcome and core == peer_core \
                    and features != peer_features:
                kind = "same-outcome-different-schedule"
                strength = 2
            elif (peer_outcome == profile.outcome and similarity < 0.65
                  and strong_unique):
                kind = "same-outcome-different-history"
                strength = 1
            else:
                continue
            candidates.append((strength, similarity, label, kind))
        if not candidates:
            return None, None
        _, _, label, kind = max(candidates)
        return label, kind

    def assess(self, profile: RunProfile) -> IndexDecision:
        signature = _signature(profile)
        previous = self.seen_runs.get(profile.label)
        if previous is not None:
            if (previous.get("signature") == signature
                    and previous.get("outcome") == profile.outcome):
                return IndexDecision(
                    profile.label, "already-seen", 0.0, signature, (), (), (),
                    None, None, None, None,
                    ("same labelled history is already indexed",),
                )
            return IndexDecision(
                profile.label, "label-collision", 0.0, signature, (), (), (),
                None, None, None, None,
                ("run label already exists with different content or outcome",),
            )

        features = set(profile.feature_ids)
        new = {feature for feature in features if self.feature_support[feature] == 0}
        rare = {feature for feature in features if self.feature_support[feature] <= 1}
        new_relational = {
            profile.feature_families[feature]
            for feature in new
            if profile.feature_families.get(feature) in RELATIONAL_FAMILIES
            and self.family_support[profile.feature_families[feature]] == 0
        }
        nearest_run, nearest_similarity = self._nearest(profile)
        contrast_run, contrast_kind = self._contrast(profile)

        def capped_weight(features: set[str]) -> float:
            totals: Counter[str] = Counter()
            for feature in features:
                family = profile.feature_families.get(feature, "unknown")
                totals[family] += FAMILY_WEIGHTS.get(family, 1.0)
            return sum(
                min(value, FAMILY_NOVELTY_CAPS.get(family, 4.0))
                for family, value in totals.items()
            )

        new_weight = capped_weight(new)
        rare_weight = capped_weight(rare)
        score = new_weight * 4.0 + rare_weight * 0.5
        score += len(new_relational) * 6.0
        if contrast_kind == "same-history-different-outcome":
            score += 20.0
        elif contrast_kind == "same-core-different-schedule-outcome":
            score += 16.0
        elif contrast_kind:
            score += 10.0
        observation = str(profile.quality.get("observation"))
        if observation == "runner-error" and not new_relational and not contrast_kind:
            score *= 0.2

        exact_duplicate = any(
            str(record.get("signature")) == signature
            and str(record.get("outcome")) == profile.outcome
            for record in self.retained_profiles.values()
        )
        reasons = [
            f"{len(new)} feature(s) have not appeared in the index",
            f"{len(rare)} feature(s) have prior support at most one",
        ]
        if new_relational:
            reasons.append(
                "new relational families: " + ", ".join(sorted(new_relational))
            )
        if contrast_run:
            reasons.append(f"contrast {contrast_run} ({contrast_kind})")
        if exact_duplicate:
            reasons.append("feature/outcome signature duplicates a retained history")

        is_control = profile.role.lower() in {
            "baseline", "clean", "clean-control", "control"
        }
        group_control_count = sum(
            str(record.get("group")) == profile.group
            and str(record.get("role", "")).lower() in {
                "baseline", "clean", "clean-control", "control"
            }
            for record in self.retained_profiles.values()
        )
        if not self.retained_profiles:
            disposition = "retain"
            reasons.append("first history seeds the discovery index")
        elif is_control and group_control_count == 0:
            disposition = "retain"
            reasons.append("first control retained for this comparison group")
        elif is_control:
            if (group_control_count < 3 and (
                new_relational
                or (new_weight >= 8.0 and (
                    nearest_similarity is None or nearest_similarity < 0.80
                ))
            )):
                disposition = "retain"
                reasons.append("retained as bounded control-variance sample")
            else:
                disposition = "discard-control-redundant"
        elif contrast_kind or new_relational:
            disposition = "retain"
        elif exact_duplicate:
            disposition = "discard-duplicate"
        elif new_weight >= 8.0 and (nearest_similarity is None or nearest_similarity < 0.80):
            disposition = "retain"
        else:
            disposition = "discard-low-novelty"

        return IndexDecision(
            run=profile.label,
            disposition=disposition,
            priority_score=round(score, 3),
            signature=signature,
            new_features=tuple(sorted(new)[:512]),
            rare_features=tuple(sorted(rare)[:512]),
            new_relational_families=tuple(sorted(new_relational)),
            nearest_retained_run=nearest_run,
            nearest_similarity=nearest_similarity,
            contrast_run=contrast_run,
            contrast_kind=contrast_kind,
            reasons=tuple(reasons),
        )

    def record(self, profile: RunProfile, decision: IndexDecision) -> None:
        if decision.disposition in {"already-seen", "label-collision"}:
            return
        self.observed_runs += 1
        for feature in set(profile.feature_ids):
            self.feature_support[feature] += 1
        for family in set(profile.feature_families.values()):
            self.family_support[family] += 1
        self.seen_runs[profile.label] = {
            "signature": decision.signature,
            "outcome": profile.outcome,
            "disposition": decision.disposition,
        }
        if decision.retain:
            self.retained_profiles[profile.label] = {
                "signature": decision.signature,
                "role": profile.role,
                "group": profile.group,
                "outcome": profile.outcome,
                "feature_ids": list(profile.feature_ids),
                "feature_families": dict(profile.feature_families),
                "quality": dict(profile.quality),
                "surface": dict(profile.surface),
            }

    def ingest(self, profile: RunProfile) -> IndexDecision:
        decision = self.assess(profile)
        self.record(profile, decision)
        return decision

    def ingest_many(self, profiles: Sequence[RunProfile]) -> list[IndexDecision]:
        return [self.ingest(profile) for profile in profiles]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.SCHEMA,
            "meaning": (
                "Incremental corpus-retention state for semantic discovery. "
                "Retention is not a vulnerability verdict."
            ),
            "observed_runs": self.observed_runs,
            "retained_runs": len(self.retained_profiles),
            "feature_support": dict(sorted(self.feature_support.items())),
            "family_support": dict(sorted(self.family_support.items())),
            "seen_runs": dict(sorted(self.seen_runs.items())),
            "retained_profiles": dict(sorted(self.retained_profiles.items())),
        }
