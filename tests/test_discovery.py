import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from teeweaver.discovery import (
    build_discovery_bundle,
    mine_contrasts,
    mine_feature_cooccurrence,
    mine_outcome_associations,
    observe_run,
    profile_runs,
    rank_novelty,
)
from teeweaver.elements import RunHistory
from teeweaver.events import Event
from teeweaver.discovery_index import NoveltyIndex
from teeweaver.query import select_context


def event(seq, op, actor="A", **attrs):
    return Event(seq, op, actor, attrs)


def run(
    label, events, *, role="diagnostic", group="g", statuses=None,
    states=None, error=None,
):
    return RunHistory(
        label, role, group, label, tuple(events), {
            "statuses": statuses or {},
            "semantic_state_ids": states or [],
            "violations": [],
            "run_error": error,
        },
    )


class DiscoveryTests(unittest.TestCase):
    def test_extracts_cross_boundary_relations_without_verdict(self):
        history = run("rich", [
            event(1, "ffa_call_issue", actor="A", process="1", call="a",
                  action=42, object="h", generation=1, receiver="sp-a"),
            event(2, "ffa_call_issue", actor="B", process="2", call="b",
                  action=43, object="h", generation=1, receiver="sp-b"),
            event(3, "ffa_direct_message", actor="A", process="1", call="a",
                  action=42, object="h", generation=1, receiver="sp-a",
                  ioctl_result=-1),
            event(4, "ffa_access", actor="B", process="2", object="h",
                  generation=1, receiver="sp-a"),
            event(5, "reset", actor="machine", kind="cold"),
            event(6, "storage_observe", actor="B", key="k", digest="v"),
        ], error="TimeoutError: bounded deadline")
        observations = observe_run(history)
        families = {item.family for item in observations}
        self.assertTrue({
            "cross-principal", "failure-followup", "incomplete-transition",
            "lifecycle", "order", "overlap", "reset-epoch",
        }.issubset(families))
        self.assertFalse(any("vulnerability" in item.label.lower()
                             for item in observations))

    def test_feature_identity_ignores_sequence_and_timestamp_noise(self):
        left = run("left", [
            event(1, "rpc_issue", actor="A", process="1", object="x", func=2,
                  time_ns=100),
            event(2, "shm_use", actor="B", process="2", object="x",
                  time_ns=200),
        ])
        right = run("right", [
            event(101, "rpc_issue", actor="A", process="1", object="x", func=2,
                  time_ns=9000),
            event(502, "shm_use", actor="B", process="2", object="x",
                  time_ns=9900),
        ])
        self.assertEqual(
            {item.feature_id for item in observe_run(left)},
            {item.feature_id for item in observe_run(right)},
        )

    def test_extracts_session_binding_byte_and_storage_relationships(self):
        history = run("boundaries", [
            event(1, "client_open_session", actor="A", process="1", session="s"),
            event(2, "client_invoke", actor="B", process="2", session="s",
                  operation="o"),
            event(3, "rpc_reply", request="r1", claims_request="r2", func=2),
            event(4, "object_verify", object="ta", digest="aa"),
            event(5, "object_consume", object="ta", digest="bb"),
            event(6, "storage_ack", key="k", digest="new"),
            event(7, "storage_observe", key="k", digest="old"),
        ])
        observations = observe_run(history)
        families = {item.family for item in observations}
        self.assertTrue({
            "byte-continuity", "cross-principal", "identity-binding",
            "lifecycle", "value-transition",
        }.issubset(families))
        self.assertTrue(any(item.key == "request-claim:rpc_reply:different"
                            for item in observations))
        self.assertTrue(any(item.key == "verify-consume:different"
                            for item in observations))
        self.assertTrue(any(item.key == "storage-ack-observe:different"
                            for item in observations))

    def test_extracts_runtime_topology_progress_and_retry_relationships(self):
        history = run("dynamic-topology", [
            event(1, "rpc_call_issue", actor="A", process="1", call="outer",
                  object="h", session="same"),
            event(2, "rpc_call_issue", actor="A", process="1", call="inner",
                  object="h"),
            event(3, "rpc_reply", actor="B", process="2", call="inner",
                  object="h", ioctl_result=-1),
            event(4, "rpc_reply", actor="A", process="1", call="outer",
                  object="h", ioctl_result=0),
            event(5, "retry", actor="A", ioctl_result=-1),
            event(6, "retry", actor="A", ioctl_result=0),
            event(7, "poll"), event(8, "yield"),
            event(9, "poll"), event(10, "yield"),
            event(11, "poll"), event(12, "yield"),
            event(13, "reset", actor="machine"),
            event(14, "client_invoke", session="same"),
        ])
        families = {item.family for item in observe_run(history)}
        self.assertTrue({
            "epoch-continuity", "principal-handoff", "progress-cycle",
            "reentrancy", "retry-transition",
        }.issubset(families))

    def test_runtime_identity_alias_uses_relationship_not_raw_value(self):
        left = run("left-alias", [
            event(1, "dispatch", call="secret-a", request="secret-a"),
        ])
        right = run("right-alias", [
            event(1, "dispatch", call="different", request="different"),
        ])
        left_alias = {
            item.feature_id for item in observe_run(left)
            if item.family == "identity-alias"
        }
        right_alias = {
            item.feature_id for item in observe_run(right)
            if item.family == "identity-alias"
        }
        self.assertEqual(left_alias, right_alias)
        self.assertTrue(left_alias)

    def test_semantic_state_features_use_bounded_stable_sketch(self):
        history = run("large", [], states=[f"state-{index}" for index in range(2000)])
        observations = observe_run(history)
        states = [item for item in observations if item.family == "semantic-state"]
        self.assertEqual(512, len(states))
        cardinality = [item for item in observations
                       if item.key.startswith("semantic-states:")]
        self.assertEqual(1, len(cardinality))

    def test_novel_relational_run_outranks_duplicate_control(self):
        control = run("control", [
            event(1, "rpc_issue", actor="A", process="1", func=2),
            event(2, "rpc_reply", actor="A", process="1", func=2),
        ], role="control")
        duplicate = run("duplicate", [
            event(1, "rpc_issue", actor="A", process="1", func=2),
            event(2, "rpc_reply", actor="A", process="1", func=2),
        ])
        novel = run("novel", [
            event(1, "ffa_share", actor="A", process="1", object="h",
                  generation=1, receiver="sp"),
            event(2, "ffa_access", actor="B", process="2", object="h",
                  generation=1, receiver="sp"),
        ])
        profiles, _ = profile_runs([control, duplicate, novel])
        queue = rank_novelty(profiles, budget=3)
        self.assertEqual("novel", queue[0].run)
        self.assertNotIn("control", {item.run for item in queue})
        self.assertIn("cross-principal", queue[0].relational_families)
        self.assertGreater(
            len(queue[0].control_unseen_features),
            len(next(item for item in queue if item.run == "duplicate")
                .control_unseen_features),
        )

    def test_queue_is_deterministic(self):
        histories = [
            run("a", [event(1, "rpc_issue", func=1)]),
            run("b", [event(1, "rpc_issue", func=2)]),
            run("c", [event(1, "storage_ack", key="x")]),
        ]
        profiles, _ = profile_runs(histories)
        first = [item.as_dict() for item in rank_novelty(profiles)]
        second = [item.as_dict() for item in rank_novelty(profiles)]
        self.assertEqual(first, second)

    def test_no_control_corpus_does_not_claim_control_unseen_features(self):
        history = run("only", [event(1, "rpc_issue", func=1)])
        profiles, _ = profile_runs([history])
        entry = rank_novelty(profiles)[0]
        self.assertEqual((), entry.control_unseen_features)
        self.assertTrue(any("no control-role" in reason for reason in entry.reasons))

    def test_same_group_contrast_is_exposed(self):
        left = run("left", [event(1, "rpc_issue", func=1)],
                   statuses={"test": "0"})
        right = run("right", [event(1, "rpc_issue", func=1),
                              event(2, "shm_release")],
                    statuses={"test": "1"})
        profiles, _ = profile_runs([left, right])
        queue = rank_novelty(profiles)
        self.assertTrue(all(item.contrast_run for item in queue))
        self.assertTrue(all(item.contrast_kind == "same-group-different-outcome"
                            for item in queue))

    def test_bundle_contains_lifetime_graph_and_ai_boundary(self):
        history = run("owner", [
            event(1, "ffa_share", process="1", object="h", generation=7,
                  receiver="sp"),
            event(2, "ffa_access", actor="B", process="2", object="h",
                  generation=7, receiver="sp"),
        ])
        bundle = build_discovery_bundle(
            [history], [], spec="synthetic.json", budget=1
        )
        self.assertEqual("teeweaver-discovery-v1", bundle["schema"])
        self.assertIn("no record", bundle["purpose"].lower())
        self.assertIn("downstream AI", bundle["purpose"])
        node_kinds = {item["kind"] for item in bundle["semantic_graph"]["nodes"]}
        relations = {item["relation"] for item in bundle["semantic_graph"]["edges"]}
        self.assertIn("lifetime", node_kinds)
        self.assertIn("generation-of", relations)
        self.assertIn("acts-on", relations)
        contract = bundle["ai_experiment_contract"]
        self.assertIn("interprets security meaning", contract["boundary"])

    def test_graph_models_non_object_resources(self):
        history = run("session", [
            event(1, "client_open_session", session="s", operation="o"),
            event(2, "client_invoke", session="s", operation="o"),
        ])
        bundle = build_discovery_bundle([history], [], spec="synthetic.json")
        resources = [
            item for item in bundle["semantic_graph"]["nodes"]
            if item["kind"] == "resource"
        ]
        self.assertEqual({"session", "operation"},
                         {item["resource_type"] for item in resources})

    def test_feature_catalog_merges_support_across_runs(self):
        first = run("first", [event(1, "rpc_issue", func=2)])
        second = run("second", [event(9, "rpc_issue", func=2)])
        bundle = build_discovery_bundle(
            [first, second], [], spec="synthetic.json"
        )
        feature = next(
            item for item in bundle["feature_catalog"]
            if item["key"] == "rpc_issue[func=2]"
        )
        self.assertEqual(2, feature["support_count"])
        self.assertEqual(["first", "second"], feature["support_runs"])

    def test_generic_differential_miners_find_cross_run_structure(self):
        runs = [
            run("a1", [event(1, "rpc_issue", func=1),
                       event(2, "shm_use", actor="B")],
                statuses={"test": "0"}),
            run("a2", [event(1, "rpc_issue", func=1),
                       event(2, "shm_use", actor="B")],
                statuses={"test": "0"}),
            run("b", [event(1, "rpc_issue", func=1),
                      event(2, "shm_release", actor="B")],
                statuses={"test": "1"}),
            run("b2", [event(1, "rpc_issue", func=1),
                       event(2, "shm_release", actor="B")],
                statuses={"test": "1"}),
        ]
        profiles, _ = profile_runs(runs)
        contrasts = mine_contrasts(profiles)
        associations = mine_outcome_associations(profiles)
        cooccurrence = mine_feature_cooccurrence(profiles)
        self.assertTrue(contrasts)
        self.assertTrue(any(item["kind"] == "different-outcome-nearby-history"
                            for item in contrasts))
        self.assertTrue(associations)
        self.assertTrue(all("caus" in item["meaning"] or "unobserved" in item["meaning"]
                            for item in associations))
        self.assertTrue(cooccurrence)

    def test_outcomes_do_not_leak_into_history_or_association_features(self):
        runs = [
            run("same-zero", [event(1, "rpc_issue", func=1)],
                statuses={"test": "0"}),
            run("same-one", [event(1, "rpc_issue", func=1)],
                statuses={"test": "1"}),
            run("other-zero", [event(1, "rpc_issue", func=2)],
                statuses={"test": "0"}),
            run("other-one", [event(1, "rpc_issue", func=2)],
                statuses={"test": "1"}),
        ]
        profiles, _ = profile_runs(runs)
        contrasts = mine_contrasts(profiles)
        self.assertTrue(any(
            item["kind"] == "same-history-different-outcome"
            for item in contrasts
        ))
        associations = mine_outcome_associations(profiles)
        self.assertTrue(all(item["family"] != "outcome"
                            for item in associations))

    def test_outcome_associations_do_not_cross_workload_groups(self):
        runs = [
            run("a1", [event(1, "rpc_issue", func=1)], group="a",
                statuses={"test": "0"}),
            run("a2", [event(1, "rpc_issue", func=1)], group="a",
                statuses={"test": "0"}),
            run("b1", [event(1, "rpc_issue", func=2)], group="b",
                statuses={"test": "1"}),
            run("b2", [event(1, "rpc_issue", func=2)], group="b",
                statuses={"test": "1"}),
        ]
        profiles, _ = profile_runs(runs)
        self.assertEqual([], mine_outcome_associations(profiles))

    def test_contrast_separates_core_structure_from_schedule(self):
        serial = run("serial", [
            event(1, "rpc_issue", actor="A", process="1", call="a"),
            event(2, "rpc_reply", actor="A", process="1", call="a"),
            event(3, "shm_issue", actor="B", process="2", call="b"),
            event(4, "shm_reply", actor="B", process="2", call="b"),
        ], statuses={"test": "0"})
        interleaved = run("interleaved", [
            event(1, "rpc_issue", actor="A", process="1", call="a"),
            event(2, "shm_issue", actor="B", process="2", call="b"),
            event(3, "shm_reply", actor="B", process="2", call="b"),
            event(4, "rpc_reply", actor="A", process="1", call="a"),
        ], statuses={"test": "1"})
        profiles, _ = profile_runs([serial, interleaved])
        contrasts = mine_contrasts(profiles)
        self.assertEqual("same-core-different-schedule-outcome",
                         contrasts[0]["kind"])
        self.assertEqual(1.0, contrasts[0]["core_feature_jaccard"])

    def test_quality_metadata_distinguishes_bounded_incomplete_history(self):
        history = run("hang", [
            event(1, "ffa_call_issue", call="x", action=42),
        ], error="TimeoutError: bounded deadline")
        profiles, _ = profile_runs([history])
        self.assertEqual("bounded-incomplete",
                         profiles[0].quality["observation"])
        self.assertEqual(1, profiles[0].quality["unmatched_call_issues"])

    def test_incremental_index_discards_duplicate_and_retains_relation(self):
        control = run("control", [event(1, "rpc_issue", func=2)], role="control")
        duplicate = run("duplicate", [event(1, "rpc_issue", func=2)])
        relational = run("relational", [
            event(1, "ffa_share", actor="A", process="1", object="h",
                  generation=1),
            event(2, "ffa_access", actor="B", process="2", object="h",
                  generation=1),
        ])
        profiles, _ = profile_runs([control, duplicate, relational])
        index = NoveltyIndex()
        decisions = index.ingest_many(profiles)
        self.assertEqual("retain", decisions[0].disposition)
        self.assertEqual("discard-duplicate", decisions[1].disposition)
        self.assertEqual("retain", decisions[2].disposition)
        self.assertIn("cross-principal", decisions[2].new_relational_families)
        self.assertEqual(2, len(index.retained_profiles))

    def test_incremental_index_roundtrip_and_reingest_are_stable(self):
        history = run("one", [event(1, "rpc_issue", func=7)])
        profile = profile_runs([history])[0][0]
        index = NoveltyIndex()
        self.assertTrue(index.ingest(profile).retain)
        restored = NoveltyIndex.from_dict(index.as_dict())
        repeated = restored.ingest(profile)
        self.assertEqual("already-seen", repeated.disposition)
        self.assertEqual(1, restored.observed_runs)

    def test_incremental_index_rejects_label_collision(self):
        first = run("same", [event(1, "rpc_issue", func=1)])
        changed = run("same", [event(1, "rpc_issue", func=2)])
        first_profile = profile_runs([first])[0][0]
        changed_profile = profile_runs([changed])[0][0]
        index = NoveltyIndex()
        index.ingest(first_profile)
        decision = index.ingest(changed_profile)
        self.assertEqual("label-collision", decision.disposition)
        self.assertEqual(1, index.observed_runs)

    def test_bounded_ai_context_selects_rank_and_graph_neighborhood(self):
        histories = [
            run("control", [event(1, "rpc_issue", func=1)], role="control"),
            run("candidate", [
                event(1, "ffa_share", actor="A", process="1", object="h",
                      generation=1, receiver="sp"),
                event(2, "ffa_access", actor="B", process="2", object="h",
                      generation=1, receiver="sp"),
            ]),
        ]
        bundle = build_discovery_bundle(
            histories, [], spec="synthetic.json", budget=2
        )
        context = select_context(
            bundle, rank=1, max_features=3, max_edges=2
        )
        self.assertEqual("teeweaver-ai-context-v1", context["schema"])
        self.assertEqual(["candidate"],
                         [item["label"] for item in context["selected_runs"]])
        self.assertEqual(["control"],
                         [item["label"] for item in context["comparison_runs"]])
        self.assertLessEqual(len(context["features"]), 3)
        self.assertLessEqual(
            len(context["selected_runs"][0]["feature_ids"]), 3
        )
        self.assertLessEqual(len(context["graph_neighborhood"]["edges"]), 2)
        self.assertGreater(context["truncation"]["features_omitted"], 0)
        self.assertIsNotNone(context["comparison_delta"])
        self.assertGreater(
            context["truncation"]["profile_feature_references_omitted"], 0
        )
        self.assertIn("not a vulnerability verdict", context["meaning"])

    def test_ai_context_can_select_feature_support_runs(self):
        history = run("one", [event(1, "rpc_issue", func=9)])
        bundle = build_discovery_bundle([history], [], spec="synthetic.json")
        feature = next(
            item["feature_id"] for item in bundle["feature_catalog"]
            if item["key"] == "rpc_issue[func=9]"
        )
        context = select_context(bundle, feature=feature)
        self.assertEqual("feature", context["selector"]["kind"])
        self.assertEqual(["one"],
                         [item["label"] for item in context["selected_runs"]])

    def test_ai_context_rejects_ambiguous_selector(self):
        history = run("one", [event(1, "rpc_issue", func=9)])
        bundle = build_discovery_bundle([history], [], spec="synthetic.json")
        with self.assertRaises(ValueError):
            select_context(bundle, run="one", rank=1)


if __name__ == "__main__":
    unittest.main()
