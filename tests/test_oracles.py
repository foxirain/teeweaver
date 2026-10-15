import sys
import unittest
import tempfile
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from teeweaver.events import Event
from teeweaver.campaign import (
    assess_run,
    inventory,
    inventory_ffa,
    plan_faults,
    plan_ffa_faults,
)
from teeweaver.freeze import aggregate_digest, build_manifest, verify_manifest
from teeweaver.minimize import ddmin
from teeweaver.oracles import check, evaluate
from teeweaver.promotion import decide_promotion
from teeweaver.scheduler import pct_schedule
from teeweaver.trace import read_jsonl
from teeweaver.workloads import load_workloads


def event(seq, op, actor="test", **attrs):
    return Event(seq=seq, op=op, actor=actor, attrs=attrs)


class OracleTests(unittest.TestCase):
    def test_clean_rpc_and_lifetime(self):
        events = [
            event(1, "shm_register", object="7", generation=1, owner="A"),
            event(2, "rpc_issue", request="11", func=2, session="A", generation=1),
            event(3, "rpc_reply", request="11", func=2, session="A", generation=1),
            event(4, "shm_use", object="7", generation=1, owner="A"),
            event(5, "shm_release", object="7", generation=1),
        ]
        violations, stimuli, coverage = check(events)
        self.assertEqual([], violations)
        self.assertEqual([], stimuli)
        self.assertEqual(len(events), coverage)

    def test_cross_binding_stimulus_alone_is_not_a_vulnerability(self):
        events = [
            event(1, "rpc_issue", request="11", func=2, session="A"),
            event(2, "rpc_issue", request="12", func=2, session="B"),
            event(3, "rpc_reply", request="11", claims_request="12", func=2, session="A"),
            event(4, "rpc_reply", request="12", claims_request="11", func=2, session="B"),
        ]
        violations, stimuli, _ = check(events)
        self.assertEqual([], violations)
        self.assertEqual(
            ["RPC_CROSS_BIND_STIMULUS", "RPC_CROSS_BIND_STIMULUS"],
            [item.code for item in stimuli],
        )

    def test_cross_binding_becomes_violation_only_when_consumed(self):
        events = [
            event(1, "rpc_issue", request="11", func=2, session="A"),
            event(2, "rpc_issue", request="12", func=2, session="B"),
            event(3, "rpc_reply", request="11", claims_request="12", func=2, session="A"),
            event(4, "rpc_reply", request="12", claims_request="11", func=2, session="B"),
            event(5, "rpc_accept", request="11", func=2, session="A"),
            event(6, "rpc_accept", request="12", func=2, session="B"),
        ]
        violations, _, _ = check(events)
        self.assertEqual(
            ["RPC_CROSS_BIND_ACCEPTED", "RPC_CROSS_BIND_ACCEPTED"],
            [item.code for item in violations],
        )

    def test_driver_rejected_reply_is_not_treated_as_delivered(self):
        events = [
            event(1, "rpc_issue", request="11", func=2, session="A"),
            event(
                2,
                "rpc_reply",
                request="11",
                claims_request="12",
                func=2,
                session="A",
                ioctl_result=-2,
            ),
            event(3, "rpc_reply", request="11", func=2, session="A", ioctl_result=0),
        ]
        violations, stimuli, _ = check(events)
        self.assertEqual([], violations)
        self.assertEqual(["RPC_REPLY_REJECTED_STIMULUS"], [x.code for x in stimuli])

    def test_memref_mutation_is_stimulus_not_violation(self):
        events = [
            event(1, "rpc_issue", request="11", func=2),
            event(
                2,
                "rpc_reply",
                request="11",
                func=2,
                fault="flip-memref",
                fault_param=2,
                fault_offset=0,
                fault_before=0x41,
                fault_after=0x40,
            ),
        ]
        violations, stimuli, _ = check(events)
        self.assertEqual([], violations)
        self.assertEqual("RPC_MEMREF_MUTATION_STIMULUS", stimuli[0].code)

    def test_cancel_then_success_is_stimulus_until_side_effect_is_proven(self):
        events = [
            event(1, "operation_issue", operation="op", session="s", command=7),
            event(2, "operation_cancel", operation="op"),
            event(3, "operation_complete", operation="op", result=0),
        ]
        violations, stimuli, _ = check(events)
        self.assertEqual([], violations)
        self.assertEqual(
            "CANCELLED_OPERATION_COMPLETED_STIMULUS", stimuli[0].code
        )

    def test_stale_generation(self):
        events = [
            event(1, "shm_register", object="7", generation=1, owner="A"),
            event(2, "shm_release", object="7", generation=1),
            event(3, "shm_register", object="7", generation=2, owner="B"),
            event(4, "shm_use", object="7", generation=1, owner="A"),
        ]
        violations, _, _ = check(events)
        self.assertEqual("SHM_STALE_USE", violations[0].code)

    def test_clean_ffa_lifecycle_with_two_retrieves(self):
        events = [
            event(1, "ffa_share", object="h", generation=1, receiver="sp"),
            event(2, "ffa_retrieve", object="h", generation=1, receiver="sp"),
            event(3, "ffa_retrieve", object="h", generation=1, receiver="sp"),
            event(4, "ffa_access", object="h", generation=1,
                  receiver="sp", access="read"),
            event(5, "ffa_relinquish", object="h", generation=1,
                  receiver="sp"),
            event(6, "ffa_relinquish", object="h", generation=1,
                  receiver="sp"),
            event(7, "ffa_reclaim", object="h", generation=1),
        ]
        violations, _, _ = check(events)
        self.assertEqual([], violations)

    def test_ffa_reclaim_with_live_receiver_is_violation(self):
        events = [
            event(1, "ffa_share", object="h", generation=1, receiver="sp"),
            event(2, "ffa_retrieve", object="h", generation=1, receiver="sp"),
            event(3, "ffa_reclaim", object="h", generation=1),
        ]
        violations, _, _ = check(events)
        self.assertEqual("FFA_RECLAIM_WITH_LIVE_RECEIVER", violations[0].code)

    def test_ffa_stale_retrieve_and_access_are_accepted_violations(self):
        events = [
            event(1, "ffa_share", object="h", generation=1, receiver="sp"),
            event(2, "ffa_reclaim", object="h", generation=1),
            event(3, "ffa_retrieve", object="h", generation=1, receiver="sp"),
            event(4, "ffa_access", object="h", generation=1,
                  receiver="sp", access="write"),
        ]
        violations, _, _ = check(events)
        self.assertEqual(
            ["FFA_STALE_RETRIEVE_ACCEPTED", "FFA_ACCESS_AFTER_RECLAIM"],
            [item.code for item in violations],
        )

    def test_ffa_fault_is_stimulus_not_violation(self):
        events = [event(1, "ffa_fault", fault="duplicate", target="reclaim")]
        violations, stimuli, _ = check(events)
        self.assertEqual([], violations)
        self.assertEqual("FFA_ADVERSARIAL_TRANSITION_STIMULUS", stimuli[0].code)

    def test_authenticated_bytes_must_be_consumed(self):
        events = [
            event(1, "object_verify", object="ta", generation=4, digest="good"),
            event(2, "object_consume", object="ta", generation=4, digest="evil"),
        ]
        violations, _, _ = check(events)
        self.assertEqual("VERIFY_USE_DRIFT", violations[0].code)

    def test_delta_minimizer_removes_noise(self):
        events = [
            event(1, "reset"),
            event(2, "rpc_issue", request="11"),
            event(3, "reset"),
            event(4, "shm_use", object="9", generation=1),
            event(5, "reset"),
        ]

        def interesting(candidate):
            violations, _, _ = check(candidate)
            return any(v.code == "SHM_STALE_USE" for v in violations)

        minimized = ddmin(events, interesting)
        self.assertEqual(["shm_use"], [item.op for item in minimized])

    def test_pct_is_reproducible_and_preserves_actor_order(self):
        actors = {"A": ["a1", "a2", "a3"], "B": ["b1", "b2"]}
        first = pct_schedule(actors, seed=99, depth=2)
        second = pct_schedule(actors, seed=99, depth=2)
        self.assertEqual(first, second)
        self.assertEqual(["a1", "a2", "a3"], [x.action for x in first if x.actor == "A"])
        self.assertEqual(["b1", "b2"], [x.action for x in first if x.actor == "B"])

    def test_semantic_state_ids_are_stable(self):
        events = [
            event(1, "rpc_issue", request="11", func=2),
            event(2, "rpc_reply", request="11", func=2),
        ]
        first = evaluate(events)[2]
        second = evaluate(events)[2]
        self.assertEqual(first, second)
        self.assertEqual(2, len(first))

    def test_semantic_states_ignore_ephemeral_identity_names(self):
        first = [
            event(1, "rpc_issue", request="11", func=2),
            event(2, "rpc_reply", request="11", func=2),
        ]
        second = [
            event(1, "rpc_issue", request="9876", func=2),
            event(2, "rpc_reply", request="9876", func=2),
        ]
        self.assertEqual(evaluate(first)[2], evaluate(second)[2])

    def test_semantic_states_ignore_absolute_generation_counter(self):
        first = [
            event(1, "shm_register", object="1", generation=2),
            event(2, "shm_use", object="1", generation=2),
        ]
        second = [
            event(1, "shm_register", object="99", generation=200),
            event(2, "shm_use", object="99", generation=200),
        ]
        self.assertEqual(evaluate(first)[2], evaluate(second)[2])

    def test_trace_reader_reindexes_cross_process_sequences(self):
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8") as stream:
            stream.write(json.dumps({"seq": 10, "op": "reset"}) + "\n")
            stream.write(json.dumps({"seq": 1, "op": "reset"}) + "\n")
            stream.flush()
            events = read_jsonl(stream.name)
        self.assertEqual([1, 2], [item.seq for item in events])
        self.assertEqual([10, 1], [item.get("source_seq") for item in events])

    def test_trace_reader_discards_stale_errno_after_success(self):
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8") as stream:
            stream.write(json.dumps({
                "seq": 1, "op": "ffa_direct_message",
                "ioctl_result": 0, "ioctl_errno": 16,
            }) + "\n")
            stream.flush()
            events = read_jsonl(stream.name)
        self.assertEqual(0, events[0].get("ioctl_errno"))

    def test_trace_reader_normalizes_cross_process_ffa_generations(self):
        values = [
            {"seq": 1, "time_ns": 1, "op": "ffa_share", "actor": "a",
             "process": "10", "object": "h", "generation": 1},
            {"seq": 2, "time_ns": 2, "op": "ffa_reclaim", "actor": "a",
             "process": "10", "object": "h", "generation": 1},
            {"seq": 1, "time_ns": 3, "op": "ffa_share", "actor": "b",
             "process": "20", "object": "h", "generation": 1},
            {"seq": 2, "time_ns": 4, "op": "ffa_retrieve", "actor": "b",
             "process": "20", "object": "h", "generation": 1},
        ]
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8") as stream:
            for value in values:
                stream.write(json.dumps(value) + "\n")
            stream.flush()
            events = read_jsonl(stream.name)
        self.assertEqual([1, 1, 2, 2], [event.get("generation") for event in events])
        self.assertEqual([1, 1, 1, 1], [event.get("local_generation") for event in events])

    def test_campaign_plan_is_deterministic_and_protocol_only(self):
        events = [
            event(1, "rpc_issue", request="1", func=2, num_params=3),
            event(2, "rpc_reply", request="1", func=2, num_params=3),
            event(3, "rpc_issue", request="1", func=7, num_params=2),
        ]
        surface = inventory(events)
        self.assertEqual([(2, 1, 3, ()), (7, 1, 2, ())], [
            (x.func, x.occurrences, x.max_params, x.memref_positions) for x in surface
        ])
        first = plan_faults(events, seed=17, budget=6)[1]
        second = plan_faults(events, seed=17, budget=6)[1]
        self.assertEqual(first, second)
        serialized = " ".join(item.rule for item in first).lower()
        self.assertNotIn("cve", serialized)
        self.assertNotIn("ghsa", serialized)
        self.assertEqual(
            {"cross-bind", "delay", "return-code"},
            {item.family for item in first},
        )

    def test_campaign_derives_memref_faults_from_observed_schema(self):
        events = [
            event(1, "rpc_issue", request="1", func=2, num_params=3,
                  memref_mask=0b110),
        ]
        surface, plans = plan_faults(events, seed=1, budget=4)
        self.assertEqual((1, 2), surface[0].memref_positions)
        self.assertIn("memref", {plan.family for plan in plans})

    def test_ffa_campaign_is_derived_from_observed_actions(self):
        events = [
            event(1, "ffa_direct_message", action=5),
            event(2, "ffa_direct_message", action=6),
            event(3, "ffa_reclaim_attempt"),
        ]
        surface = inventory_ffa(events)
        self.assertEqual(
            [("message", 5, True), ("message", 6, True), ("reclaim", None, True)],
            [(x.kind, x.action, x.carries_handle) for x in surface],
        )
        first = plan_ffa_faults(events, seed=23, budget=6)[1]
        second = plan_ffa_faults(events, seed=23, budget=6)[1]
        self.assertEqual(first, second)
        serialized = " ".join(item.rule for item in first).lower()
        self.assertNotIn("cve", serialized)
        self.assertNotIn("ghsa", serialized)
        self.assertTrue(all(item.rule.startswith("ffa_") for item in first))

    def test_campaign_assessment_does_not_call_status_failure_a_bug(self):
        baseline = {"semantic_state_ids": ["a"], "statuses": {"1004": "0"}}
        observed = {
            "semantic_state_ids": ["a", "b"],
            "statuses": {"1004": "1"},
            "stimuli": [],
            "violations": [],
        }
        result = assess_run(baseline, observed, process_returncode=0)
        self.assertEqual("behavioral-symptom", result.classification)
        self.assertEqual(("b",), result.new_semantic_states)
        self.assertEqual(1, result.new_semantic_state_count)

    def test_campaign_assessment_promotes_only_accepted_violation(self):
        baseline = {"semantic_state_ids": ["a"], "statuses": {"1004": "0"}}
        observed = {
            "semantic_state_ids": ["a"],
            "statuses": {"1004": "0"},
            "stimuli": [{"code": "RPC_CROSS_BIND_STIMULUS"}],
            "violations": [{"code": "RPC_CROSS_BIND_ACCEPTED"}],
        }
        result = assess_run(baseline, observed, process_returncode=0)
        self.assertEqual("violation-candidate", result.classification)

    def test_missing_status_after_timeout_is_runner_failure(self):
        baseline = {"semantic_state_ids": ["a"], "statuses": {"1004": "0"}}
        observed = {
            "semantic_state_ids": ["a"],
            "statuses": {},
            "stimuli": [],
            "violations": [],
            "run_error": "TimeoutError: workload did not complete",
        }
        result = assess_run(baseline, observed, process_returncode=1)
        self.assertEqual("runner-failure", result.classification)
        self.assertEqual({}, result.status_delta)

    def test_target_panic_outranks_runner_timeout_but_is_not_violation(self):
        baseline = {"semantic_state_ids": ["a"], "statuses": {"test": "0"}}
        observed = {
            "semantic_state_ids": ["b"],
            "statuses": {},
            "stimuli": [],
            "violations": [],
            "target_symptoms": [{"code": "SECURE_WORLD_DATA_ABORT"}],
            "run_error": "TimeoutError: target stopped responding",
        }
        result = assess_run(baseline, observed, process_returncode=1)
        self.assertEqual("target-symptom", result.classification)
        self.assertIn("impact validation", " ".join(result.reasons))

    def test_freeze_is_advisory_blind_and_verifies_current_tree(self):
        project = Path(__file__).parents[1]
        manifest = build_manifest(project, label="unit-test")
        files = manifest["files"]
        self.assertNotIn("evaluation/known_cases.json", files)
        self.assertNotIn("results", " ".join(files))
        self.assertNotIn("instrumentation/storage_probe/storage_probe", files)
        self.assertNotIn("instrumentation/ffa_probe/ffa_probe", files)
        self.assertNotIn(
            "instrumentation/ffa_sequence_probe/ffa_sequence_probe", files
        )
        self.assertEqual(
            manifest["aggregate_sha256"], aggregate_digest(files)
        )
        self.assertTrue(verify_manifest(project, manifest).valid)

    def test_generators_do_not_import_known_case_registry(self):
        project = Path(__file__).parents[1]
        inspected = [
            project / "src/teeweaver/campaign.py",
            project / "src/teeweaver/scheduler.py",
            project / "src/teeweaver/oracles.py",
            project / "src/teeweaver/state_machine.py",
            project / "tools/run_campaign.py",
            project / "tools/plan_state_machine.py",
            project / "tools/materialize_ffa_sequence.py",
        ]
        forbidden = "known" + "_cases"
        for path in inspected:
            self.assertNotIn(forbidden, path.read_text(encoding="utf-8"))

    def test_promotion_requires_violation_and_all_evidence_gates(self):
        no_violation = decide_promotion({"violations": []}, {})
        self.assertEqual("not-a-candidate", no_violation.stage)
        summary = {"violations": [{"code": "SHM_STALE_USE"}]}
        held = decide_promotion(summary, {"supported_configuration": True})
        self.assertEqual("hold-for-validation", held.stage)
        evidence = {name: True for name in held.satisfied + held.missing}
        promoted = decide_promotion(summary, evidence)
        self.assertTrue(promoted.promotable)

    def test_workload_manifest_is_valid_and_extensible(self):
        project = Path(__file__).parents[1]
        workloads = load_workloads(project / "scenarios/workloads.json")
        self.assertEqual("parallel", workloads["load-ta-swap"].mode)
        self.assertEqual(
            ("1004", "1007"),
            tuple(test.test_id for test in workloads["load-ta-swap"].tests),
        )
        self.assertTrue(workloads["ffa-memory-lifecycle"].ffa_trace)
        self.assertEqual(
            "ffa_spmc", workloads["ffa-memory-lifecycle"].tests[0].suite
        )
        self.assertEqual(
            ("sp1", "sp2"),
            tuple(test.label for test in workloads["ffa-memory-parallel"].tests),
        )
        self.assertEqual(
            {"ffa_probe"},
            {test.program for test in workloads["ffa-memory-parallel"].tests},
        )
        self.assertFalse(workloads["ffa-memory-parallel"].campaign_eligible)


if __name__ == "__main__":
    unittest.main()
