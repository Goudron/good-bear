#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "launch_local_candidate", ROOT / "tools/launch_local_candidate.py"
)
assert SPEC and SPEC.loader
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class LocalCandidateLauncherTest(unittest.TestCase):
    def test_environment_does_not_inherit_snap_runtime(self) -> None:
        source = (ROOT / "tools/launch_local_candidate.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"LANG": "ru_RU.UTF-8"', source)
        self.assertIn('"LANGUAGE": "ru_RU:ru"', source)
        self.assertNotIn('environment = os.environ.copy()', source)
        self.assertNotIn('"SNAP"', source)

    def test_launcher_detaches_and_waits_for_profile_initialization(self) -> None:
        source = (ROOT / "tools/launch_local_candidate.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("start_new_session=True", source)
        self.assertIn('marker = profile / "compatibility.ini"', source)
        self.assertIn("process.poll()", source)

    def test_all_transient_paths_are_project_owned(self) -> None:
        self.assertEqual(LAUNCHER.RUN_CANDIDATES, ROOT / "artifacts/run-candidates")
        self.assertEqual(LAUNCHER.RUN_PROFILES, ROOT / "artifacts/run-profiles")


if __name__ == "__main__":
    unittest.main()
