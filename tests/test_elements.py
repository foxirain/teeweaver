import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from teeweaver.elements import (
    RunHistory,
    mine_aba_cycles,
    mine_failure_residue,
    mine_hidden_global_resources,
    mine_non_commutative_pairs,
    mine_non_terminating_transitions,
    mine_ownership_transfer,
    mine_reset_survivors,
    mine_serialization_domains,
    mine_state_aliases,
)
from teeweaver.events import Event


def event(seq, op, actor="A", **attrs):
    return Event(seq, op, actor, attrs)


def run(label, events, *, group="g", statuses=None, states=None, error=None):
    return RunHistory(
        label, "diagnostic", group, label, tuple(events), {
            "statuses": statuses or {},
            "semantic_state_ids": states or [],
            "violations": [],
            "run_error": error,
        }
    )


class ElementMinerTests(unittest.TestCase):
    def assert_kind(self, elements, kind):
        self.assertTrue(elements)
        self.assertTrue(all(item.kind == kind for item in elements))
        self.assertTrue(all(item.not_a_vulnerability for item in elements))

    def test_hidden_global_resource_crosses_processes(self):
        history = run("shared", [
            event(1, "ffa_share", process="1", object="10", generation=1),
            event(2, "ffa_access", actor="B", process="2", object="10", generation=1),
        ])
        self.assert_kind(mine_hidden_global_resources([history]),
                         "hidden-global-resource")

    def test_non_commutative_pair_requires_both_orders_and_outcome_delta(self):
        ab = run("ab", [event(1, "rpc_issue", actor="A", func=1),
                         event(2, "shm_release", actor="B")],
                 statuses={"t": "0"})
        ba = run("ba", [event(1, "shm_release", actor="B"),
                         event(2, "rpc_issue", actor="A", func=1)],
                 statuses={"t": "1"})
        self.assert_kind(mine_non_commutative_pairs([ab, ba]),
                         "non-commutative-action-pair")

    def test_failure_residue_requires_later_use_before_cleanup(self):
        history = run("residue", [
            event(1, "ffa_direct_message", object="h", receiver="sp",
                  ioctl_result=-1),
            event(2, "ffa_access", object="h", receiver="sp"),
        ])
        self.assert_kind(mine_failure_residue([history]),
                         "failure-residual-state")

    def test_ownership_transfer(self):
        history = run("owner", [event(
            1, "ffa_share", object="h", generation=1,
            owner="normal-world-1", receiver="40001",
        )])
        self.assert_kind(mine_ownership_transfer([history]), "ownership-transfer")

    def test_aba_reuse(self):
        history = run("aba", [
            event(1, "shm_register", object="7", generation=1),
            event(2, "shm_release", object="7", generation=1),
            event(3, "shm_register", object="7", generation=2),
        ])
        self.assert_kind(mine_aba_cycles([history]), "aba-reuse-cycle")

    def test_hidden_serialization_domain(self):
        history = run("contended", [
            event(1, "ffa_direct_message", actor="A", process="1", action=42,
                  ioctl_result=-1, ioctl_errno=16),
            event(2, "ffa_direct_message", actor="B", process="2", action=42,
                  ioctl_result=0, ioctl_errno=0),
        ])
        self.assert_kind(mine_serialization_domains([history]),
                         "hidden-serialization-domain")

    def test_reset_surviving_state(self):
        history = run("reset", [
            event(1, "storage_ack", key="k", digest="new"),
            event(2, "reset", kind="replay"),
            event(3, "storage_observe", key="k", digest="old"),
        ])
        self.assert_kind(mine_reset_survivors([history]), "reset-surviving-state")

    def test_non_terminating_transition(self):
        history = run("hang", [
            event(1, "ffa_call_issue", call="1:2:message:1:0", action=3),
        ], error="TimeoutError: bounded deadline")
        self.assert_kind(mine_non_terminating_transitions([history]),
                         "non-terminating-transition")

    def test_state_aliasing(self):
        left = run("left", [], statuses={"t": "0"}, states=["a", "b", "c"])
        right = run("right", [], statuses={"t": "0"}, states=["x", "y", "z"])
        self.assert_kind(mine_state_aliases([left, right]), "state-aliasing")


if __name__ == "__main__":
    unittest.main()
