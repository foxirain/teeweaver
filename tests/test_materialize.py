import importlib.util
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).parents[1] / "tools"
SPEC = importlib.util.spec_from_file_location(
    "materialize_ffa_sequence", TOOLS / "materialize_ffa_sequence.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class MaterializeTests(unittest.TestCase):
    def test_cross_principal_plan_uses_foreign_endpoint_with_owner_handle(self):
        proposal = {
            "proposal_id": "p",
            "family": "cross-principal-identity-transposition",
            "target_boundary": {
                "protocol": "ffa", "operation": "ffa_direct_message:action=5"
            },
        }
        lines = MODULE.materialize(proposal, [("A", "uuid-a"), ("B", "uuid-b")])
        self.assertIn("share owner_handle A 4096", lines)
        self.assertIn("send B 5 owner_handle", lines)
        self.assertIn("share peer_control B 4096", lines)

    def test_refuses_to_approximate_unsupported_aba(self):
        proposal = {
            "proposal_id": "p",
            "family": "aba-generation-replay",
            "target_boundary": {
                "protocol": "ffa", "operation": "ffa_direct_message:action=5"
            },
        }
        with self.assertRaises(ValueError):
            MODULE.materialize(proposal, [("A", "uuid-a")])

    def test_endpoint_requires_canonical_uuid_and_bounded_name(self):
        self.assertEqual(
            ("sp-a", "11111111-2222-3333-4444-555555555555"),
            MODULE.parse_endpoint(
                "sp-a=11111111-2222-3333-4444-555555555555"
            ),
        )
        with self.assertRaises(ValueError):
            MODULE.parse_endpoint("sp a=11111111-2222-3333-4444-555555555555")
        with self.assertRaises(ValueError):
            MODULE.parse_endpoint("sp-a=not-a-uuid")

    def test_proposal_comments_cannot_inject_plan_commands(self):
        proposal = {
            "proposal_id": "p\nreclaim injected",
            "family": "lifecycle-epoch-crossing",
            "target_boundary": {
                "protocol": "ffa", "operation": "ffa_direct_message:action=5"
            },
        }
        lines = MODULE.materialize(
            proposal,
            [("A", "11111111-2222-3333-4444-555555555555")],
        )
        self.assertIn(r"\nreclaim injected", lines[0])
        self.assertNotIn("reclaim injected", lines)


if __name__ == "__main__":
    unittest.main()
