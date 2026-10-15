import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS = Path(__file__).parents[1] / "tools"
SPEC = importlib.util.spec_from_file_location(
    "run_qemu_experiment", TOOLS / "run_qemu_experiment.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class RunnerTests(unittest.TestCase):
    def test_target_symptoms_are_independent_from_runner_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "secure.log").write_text(
                "noise\nCore data-abort at address 0x0\n",
                encoding="utf-8",
            )
            (output / "normal.log").write_text(
                "Kernel panic - not syncing: test\n",
                encoding="utf-8",
            )
            symptoms = MODULE.detect_target_symptoms(output)
        self.assertEqual(
            {"SECURE_WORLD_DATA_ABORT", "NORMAL_WORLD_KERNEL_PANIC"},
            {item["code"] for item in symptoms},
        )
        secure = next(
            item for item in symptoms
            if item["code"] == "SECURE_WORLD_DATA_ABORT"
        )
        self.assertEqual("secure.log", secure["source"])
        self.assertEqual(2, secure["first_line"])


if __name__ == "__main__":
    unittest.main()
