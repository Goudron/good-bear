#!/usr/bin/env python3
"""Focused contracts for GB100-M12-07 Ubuntu-only reproducibility."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("m12_07", ROOT / "tools/run_m12_07_ubuntu_reproducibility.py")
assert SPEC and SPEC.loader
M12_07 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M12_07)


class UbuntuReproducibilityContractTest(unittest.TestCase):
    def test_windows_is_an_explicit_manual_release_blocker_not_a_result(self) -> None:
        blocker = M12_07.WINDOWS_MANUAL_RELEASE_BLOCKER
        self.assertEqual(blocker["automation"], "not-run")
        self.assertTrue(blocker["release_blocker"])
        self.assertNotIn("pass", str(blocker).lower())

    def test_normalized_comparison_rejects_any_semantic_delta(self) -> None:
        baseline = {"debian_binary": "goodbear-browser 1 amd64", "control": [], "data": []}
        self.assertEqual(M12_07.normalized_diff(baseline, dict(baseline)), [])
        changed = {**baseline, "data": [{"name": "./opt/goodbear/goodbear", "sha256": "changed"}]}
        difference = M12_07.normalized_diff(baseline, changed)
        self.assertEqual(difference[0]["section"], "data")

    def test_runner_is_host_only_and_retains_failures_in_project_quarantine(self) -> None:
        source = Path(M12_07.__file__).read_text(encoding="utf-8")
        self.assertIn("fresh host-only", source)
        self.assertIn('"docker": "not used"', source)
        self.assertIn("reproducibility-failure.json", source)
        self.assertIn("unexplained Ubuntu package delta", source)
        self.assertEqual(M12_07.EXPECTED_CANDIDATE_SHA256,
                         "b4b44e9b69f583e1de5c6a9a3a79e7731547b9c9610f2a73a8e59026f11da9f4")


if __name__ == "__main__":
    unittest.main()
