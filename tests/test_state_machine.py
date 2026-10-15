import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from teeweaver.state_machine import (
    coverage_report,
    observe_boundaries,
    proposal_report,
    synthesize_experiments,
)
from teeweaver.events import Event


def event(seq, op, actor="normal-world-A", **attrs):
    return Event(seq, op, actor, attrs)


class Run:
    def __init__(self, label, events):
        self.label = label
        self.events = tuple(events)


class DiscoveryTests(unittest.TestCase):
    def test_boundary_tuple_ignores_raw_handle_and_pid(self):
        left = [
            event(1, "ffa_share", actor="ffa-client-101", object="a001",
                  generation=1, owner="normal-world-101", receiver="32770"),
            event(2, "ffa_access", actor="ffa-client-101", object="a001",
                  generation=1, owner="normal-world-101", receiver="32770"),
        ]
        right = [
            event(1, "ffa_share", actor="ffa-client-999", object="deadbeef",
                  generation=41, owner="normal-world-999", receiver="32771"),
            event(2, "ffa_access", actor="ffa-client-999", object="deadbeef",
                  generation=41, owner="normal-world-999", receiver="32771"),
        ]
        self.assertEqual(
            [item.tuple.signature() for item in observe_boundaries(left)],
            [item.tuple.signature() for item in observe_boundaries(right)],
        )

    def test_recovered_busy_is_canonical_retry_noise(self):
        events = [
            event(1, "ffa_direct_message", action=5, receiver="32770",
                  ioctl_result=-1, ioctl_errno=16),
            event(2, "ffa_direct_message", action=5, receiver="32770",
                  ioctl_result=0, ioctl_errno=0),
        ]
        boundaries = observe_boundaries(events)
        self.assertEqual("retryable-failure", boundaries[0].tuple.outcome)
        self.assertEqual("success", boundaries[1].tuple.outcome)

    def test_generates_foreign_live_identity_transposition(self):
        history = Run("two-owners", [
            event(1, "ffa_share", actor="ffa-client-A", object="h1", generation=1,
                  owner="normal-world-A", receiver="32770"),
            event(2, "ffa_share", actor="ffa-client-B", object="h2", generation=1,
                  owner="normal-world-B", receiver="32771"),
            event(3, "ffa_retrieve", actor="ffa-client-B", object="h2", generation=1,
                  owner="normal-world-B", receiver="32771"),
        ])
        proposals = synthesize_experiments([history])
        candidate = next(item for item in proposals
                         if item.family == "cross-principal-identity-transposition")
        self.assertEqual(94, candidate.priority)
        self.assertEqual("replace-identity", candidate.mutations[0]["kind"])
        self.assertEqual("object", candidate.mutations[0]["field"])
        self.assertTrue(candidate.not_a_finding)

    def test_receiver_binding_detects_foreign_live_use(self):
        events = [
            event(1, "ffa_share", object="h", generation=1,
                  owner="normal-world-A", receiver="32770"),
            event(2, "ffa_call_issue", object="h", generation=1,
                  receiver="32771", action=5),
        ]
        boundary = observe_boundaries(events)[1].tuple
        self.assertEqual("live", boundary.lifecycle_before)
        self.assertEqual("foreign-receiver", boundary.authorization_relation)

    def test_generates_lifecycle_and_aba_replays(self):
        history = Run("reuse", [
            event(1, "shm_register", object="7", generation=1),
            event(2, "shm_use", object="7", generation=1),
            event(3, "shm_release", object="7", generation=1),
            event(4, "shm_register", object="7", generation=2),
        ])
        families = {item.family for item in synthesize_experiments([history])}
        self.assertIn("lifecycle-epoch-crossing", families)
        self.assertIn("aba-generation-replay", families)
        self.assertIn("duplicate-terminal-transition", families)

    def test_saturation_is_based_on_normalized_boundaries(self):
        runs = []
        for index in range(6):
            runs.append(Run(str(index), [
                event(1, "ffa_share", actor=f"ffa-client-{index}",
                      object=f"h{index}", generation=index + 1,
                      owner=f"normal-world-{index}", receiver=str(32770 + index)),
            ]))
        report = coverage_report(runs, saturation_window=5)
        self.assertEqual(1, report["unique_boundary_tuples"])
        self.assertTrue(report["saturation"]["saturated"])
        self.assertIn("pivot to a new boundary/workload family",
                      report["recommendations"][0])

    def test_new_boundary_family_breaks_plateau(self):
        runs = [Run("base", [event(1, "rpc_issue", request="1", func=2)])]
        runs.extend(Run(f"repeat-{index}", [
            event(1, "rpc_issue", request=str(index + 2), func=2)
        ]) for index in range(4))
        runs.append(Run("new", [
            event(1, "object_verify", object="ta", generation=1, digest="a"),
            event(2, "object_consume", object="ta", generation=1, digest="b"),
        ]))
        report = coverage_report(runs, saturation_window=2)
        self.assertFalse(report["saturation"]["saturated"])
        self.assertIn("authenticated-bytes-drift",
                      report["dimensions"]["authorization_relation"])

    def test_queue_boosts_uncovered_frontier_and_penalizes_covered_one(self):
        history = Run("two-owners", [
            event(1, "ffa_share", object="h1", generation=1,
                  owner="normal-world-A", receiver="32770"),
            event(2, "ffa_share", actor="normal-world-B", object="h2",
                  generation=1, owner="normal-world-B", receiver="32771"),
            event(3, "ffa_retrieve", actor="normal-world-B", object="h2",
                  generation=1, owner="normal-world-B", receiver="32771"),
            event(4, "ffa_relinquish", actor="normal-world-B", object="h2",
                  generation=1, owner="normal-world-B", receiver="32771"),
        ])
        report = proposal_report([history])
        proposals = report["proposals"]
        cross = next(item for item in proposals if item["family"] ==
                     "cross-principal-identity-transposition")
        lifecycle = next(item for item in proposals if item["family"] ==
                         "lifecycle-epoch-crossing")
        self.assertEqual("targets-uncovered-frontier", cross["frontier_status"])
        self.assertIn("stale-generation-use",
                      lifecycle["uncovered_frontier_targets"])
        self.assertIn("effective_priority", proposals[0])
        self.assertEqual(0, proposals[0]["queue_wave"])
        backlog = {item["frontier_target"] for item in report["adapter_backlog"]}
        self.assertIn("authenticated-byte-drift", backlog)


if __name__ == "__main__":
    unittest.main()
