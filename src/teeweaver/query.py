from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

from .discovery import RELATIONAL_FAMILIES


def _objects(values: Any) -> list[Mapping[str, Any]]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        return []
    return [item for item in values if isinstance(item, Mapping)]


def _choose_features(
    feature_ids: set[str], catalog: Mapping[str, Mapping[str, Any]], limit: int,
) -> tuple[list[Mapping[str, Any]], int]:
    values = [catalog[feature] for feature in feature_ids if feature in catalog]
    values.sort(key=lambda item: (
        0 if item.get("family") in RELATIONAL_FAMILIES else 1,
        int(item.get("support_count", 0)),
        str(item.get("feature_id", "")),
    ))
    return values[:limit], max(0, len(values) - limit)


def _bounded_profile(
    profile: Mapping[str, Any], included_features: set[str], *, list_limit: int = 64,
) -> tuple[dict[str, Any], dict[str, int]]:
    value = dict(profile)
    all_features = [str(item) for item in profile.get("feature_ids", [])]
    feature_ids = [item for item in all_features if item in included_features]
    value["feature_ids"] = feature_ids
    families = profile.get("feature_families", {})
    value["feature_families"] = {
        item: str(families[item]) for item in feature_ids
        if isinstance(families, Mapping) and item in families
    }
    value["feature_context"] = {
        "total": len(all_features),
        "included": len(feature_ids),
        "omitted": len(all_features) - len(feature_ids),
    }

    omitted: dict[str, int] = {
        "profile_feature_references": len(all_features) - len(feature_ids),
        "surface_values": 0,
    }
    surface = profile.get("surface", {})
    if isinstance(surface, Mapping):
        bounded_surface = dict(surface)
        for key in (
            "actors", "principals", "endpoints", "mutable_fields",
            "supported_interventions", "actions",
        ):
            raw = surface.get(key, [])
            if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
                continue
            bounded_surface[key] = list(raw[:list_limit])
            omitted["surface_values"] += max(0, len(raw) - list_limit)
        value["surface"] = bounded_surface
    return value, omitted


def _bounded_queue_entry(
    entry: Mapping[str, Any] | None, included_features: set[str],
) -> tuple[dict[str, Any] | None, int]:
    if entry is None:
        return None, 0
    value = dict(entry)
    omitted = 0
    for key in (
        "marginal_features", "control_unseen_features", "rare_features",
    ):
        raw = [str(item) for item in entry.get(key, [])]
        selected = [item for item in raw if item in included_features]
        value[key] = selected
        value[f"{key}_total"] = len(raw)
        omitted += len(raw) - len(selected)
    return value, omitted


def _feature_delta(
    left_labels: set[str], right_labels: set[str],
    profiles: Mapping[str, Mapping[str, Any]], included_features: set[str],
) -> dict[str, Any] | None:
    if not left_labels or not right_labels:
        return None
    left = {
        str(feature) for label in left_labels for feature in profiles[label].get(
            "feature_ids", []
        )
    }
    right = {
        str(feature) for label in right_labels for feature in profiles[label].get(
            "feature_ids", []
        )
    }
    sections = {
        "shared": left & right,
        "left_only": left - right,
        "right_only": right - left,
    }
    return {
        "left_runs": sorted(left_labels),
        "right_runs": sorted(right_labels),
        **{
            key: {
                "total": len(features),
                "included_feature_ids": sorted(features & included_features),
                "omitted": len(features - included_features),
            }
            for key, features in sections.items()
        },
    }


def select_context(
    bundle: Mapping[str, Any], *, run: str | None = None,
    feature: str | None = None, contrast: str | None = None,
    rank: int | None = None, max_features: int = 96, max_edges: int = 128,
    max_elements: int = 32,
) -> dict[str, Any]:
    """Create a bounded, provenance-preserving AI context from a discovery bundle."""

    if bundle.get("schema") != "teeweaver-discovery-v1":
        raise ValueError("unsupported discovery bundle schema")
    selectors = sum(value is not None for value in (run, feature, contrast, rank))
    if selectors > 1:
        raise ValueError("select exactly one of run, feature, contrast, or rank")
    if max_features < 1 or max_edges < 1 or max_elements < 1:
        raise ValueError("context limits must be positive")

    profiles = {
        str(item.get("label")): item for item in _objects(bundle.get("profiles"))
    }
    catalog = {
        str(item.get("feature_id")): item
        for item in _objects(bundle.get("feature_catalog"))
    }
    queue = _objects(bundle.get("discovery_queue"))
    differential = bundle.get("differential_mining", {})
    contrasts = {
        str(item.get("contrast_id")): item
        for item in _objects(
            differential.get("contrasts")
            if isinstance(differential, Mapping) else []
        )
    }

    # Keep the focal selection distinct from profiles pulled in only as
    # comparison context.  Consumers must be able to tell what the user asked
    # about from what TEEWeaver supplied to make that evidence interpretable.
    selected_runs: set[str] = set()
    comparison_runs: set[str] = set()
    selected_features: set[str] = set()
    selected_contrast: Mapping[str, Any] | None = None
    selected_queue: Mapping[str, Any] | None = None
    selector: dict[str, Any]

    if rank is not None:
        selected_queue = next(
            (item for item in queue if int(item.get("rank", -1)) == rank), None
        )
        if selected_queue is None:
            raise ValueError(f"unknown discovery queue rank: {rank}")
        run = str(selected_queue.get("run"))
        selector = {"kind": "rank", "value": rank}
    elif run is not None:
        selector = {"kind": "run", "value": run}
    elif feature is not None:
        selector = {"kind": "feature", "value": feature}
    elif contrast is not None:
        selector = {"kind": "contrast", "value": contrast}
    elif queue:
        selected_queue = queue[0]
        run = str(selected_queue.get("run"))
        selector = {"kind": "rank", "value": int(selected_queue.get("rank", 1))}
    elif profiles:
        run = sorted(profiles)[0]
        selector = {"kind": "run", "value": run}
    else:
        raise ValueError("discovery bundle contains no selectable runs")

    if run is not None:
        if run not in profiles:
            raise ValueError(f"unknown run: {run}")
        selected_runs.add(run)
        selected_features.update(str(item) for item in profiles[run].get(
            "feature_ids", []
        ))
        if selected_queue is None:
            selected_queue = next(
                (item for item in queue if str(item.get("run")) == run), None
            )
        if selected_queue:
            selected_features.update(str(item) for item in selected_queue.get(
                "marginal_features", []
            ))
            peer = selected_queue.get("contrast_run")
            if peer is not None and str(peer) in profiles:
                comparison_runs.add(str(peer))

    if feature is not None:
        if feature not in catalog:
            raise ValueError(f"unknown feature: {feature}")
        selected_features.add(feature)
        selected_runs.update(
            str(item) for item in catalog[feature].get("support_runs", [])
            if str(item) in profiles
        )

    if contrast is not None:
        if contrast not in contrasts:
            raise ValueError(f"unknown contrast: {contrast}")
        selected_contrast = contrasts[contrast]
        for key in ("left_run", "right_run"):
            label = str(selected_contrast.get(key))
            if label in profiles:
                selected_runs.add(label)
        for key in (
            "left_only_features", "right_only_features",
            "relational_unique_features",
        ):
            selected_features.update(
                str(item) for item in selected_contrast.get(key, [])
            )

    for label in selected_runs:
        selected_features.update(
            str(item) for item in profiles[label].get("feature_ids", [])
        )

    all_evidence_runs = selected_runs | comparison_runs
    for label in comparison_runs:
        selected_features.update(
            str(item) for item in profiles[label].get("feature_ids", [])
        )

    chosen_features, omitted_features = _choose_features(
        selected_features, catalog, max_features
    )
    chosen_feature_ids = {
        str(item.get("feature_id")) for item in chosen_features
    }

    graph = bundle.get("semantic_graph", {})
    graph_nodes = _objects(graph.get("nodes") if isinstance(graph, Mapping) else [])
    graph_edges = _objects(graph.get("edges") if isinstance(graph, Mapping) else [])
    run_node_ids = {
        str(item.get("id")) for item in graph_nodes
        if item.get("kind") == "run" and str(item.get("label")) in all_evidence_runs
    }
    seed_nodes = run_node_ids | chosen_feature_ids
    neighbor_edges = [
        item for item in graph_edges
        if str(item.get("source")) in seed_nodes
        or str(item.get("target")) in seed_nodes
    ]
    neighbor_edges.sort(key=lambda item: (
        0 if item.get("relation") in {
            "acts-on", "generation-of", "supported-by", "targets"
        } else 1,
        -int(item.get("count", 0)),
        str(item.get("source")), str(item.get("target")),
    ))
    chosen_edges = neighbor_edges[:max_edges]
    node_ids = set(seed_nodes)
    for item in chosen_edges:
        node_ids.add(str(item.get("source")))
        node_ids.add(str(item.get("target")))
    chosen_nodes = [item for item in graph_nodes if str(item.get("id")) in node_ids]

    relevant_elements = []
    for element in _objects(bundle.get("elements")):
        element_runs = {
            str(item.get("run")) for item in _objects(element.get("evidence"))
            if item.get("run") is not None
        }
        if element_runs & all_evidence_runs:
            relevant_elements.append(element)
    relevant_elements.sort(key=lambda item: (
        -int(item.get("score", 0)), str(item.get("element_id", "")),
    ))
    omitted_elements = max(0, len(relevant_elements) - max_elements)
    relevant_elements = relevant_elements[:max_elements]

    surfaces = {
        label: profiles[label].get("surface", {})
        for label in sorted(all_evidence_runs)
    }
    interventions = sorted({
        str(item)
        for surface in surfaces.values() if isinstance(surface, Mapping)
        for item in surface.get("supported_interventions", [])
    })
    bounded_profiles = []
    bounded_comparisons = []
    profile_feature_omissions = 0
    surface_omissions = 0
    for label in sorted(selected_runs):
        value, omitted = _bounded_profile(profiles[label], chosen_feature_ids)
        bounded_profiles.append(value)
        profile_feature_omissions += omitted["profile_feature_references"]
        surface_omissions += omitted["surface_values"]
    for label in sorted(comparison_runs - selected_runs):
        value, omitted = _bounded_profile(profiles[label], chosen_feature_ids)
        bounded_comparisons.append(value)
        profile_feature_omissions += omitted["profile_feature_references"]
        surface_omissions += omitted["surface_values"]

    if selected_contrast is not None:
        left_labels = {str(selected_contrast.get("left_run"))} & set(profiles)
        right_labels = {str(selected_contrast.get("right_run"))} & set(profiles)
    else:
        left_labels = set(selected_runs)
        right_labels = set(comparison_runs) - selected_runs
    comparison_delta = _feature_delta(
        left_labels, right_labels, profiles, chosen_feature_ids
    )
    bounded_queue, queue_feature_omissions = _bounded_queue_entry(
        selected_queue, chosen_feature_ids
    )
    return {
        "schema": "teeweaver-ai-context-v1",
        "source_schema": bundle["schema"],
        "source_bundle_sha256": hashlib.sha256(json.dumps(
            bundle, sort_keys=True, separators=(",", ":"), default=str,
        ).encode("utf-8")).hexdigest(),
        "selector": selector,
        "meaning": (
            "Bounded dynamic evidence for AI hypothesis and experiment design. "
            "This context is not a vulnerability verdict."
        ),
        "selected_runs": bounded_profiles,
        "comparison_runs": bounded_comparisons,
        "comparison_delta": comparison_delta,
        "selected_queue_entry": bounded_queue,
        "selected_contrast": selected_contrast,
        "features": chosen_features,
        "elements": relevant_elements,
        "graph_neighborhood": {
            "nodes": chosen_nodes,
            "edges": chosen_edges,
        },
        "experiment_surface": {
            "by_run": surfaces,
            "available_interventions": interventions,
        },
        "ai_request_template": {
            "hypothesis": "",
            "selected_runs": sorted(selected_runs),
            "comparison_runs": sorted(comparison_runs - selected_runs),
            "target_features": sorted(chosen_feature_ids),
            "intervention": {
                "kind": interventions[0] if interventions else "",
                "target": "",
                "parameters": {},
            },
            "controls": [],
            "requested_observations": [],
        },
        "truncation": {
            "features_omitted": omitted_features,
            "graph_edges_omitted": max(0, len(neighbor_edges) - len(chosen_edges)),
            "elements_omitted": omitted_elements,
            "profile_feature_references_omitted": profile_feature_omissions,
            "queue_feature_references_omitted": queue_feature_omissions,
            "surface_values_omitted": surface_omissions,
            "max_features": max_features,
            "max_edges": max_edges,
            "max_elements": max_elements,
        },
    }
