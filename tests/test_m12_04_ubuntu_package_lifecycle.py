#!/usr/bin/env python3
"""Focused contracts for GB100-M12-04 lifecycle evidence."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("m12_04", ROOT / "tools" / "run_m12_04_ubuntu_package_lifecycle.py")
assert SPEC and SPEC.loader
LIFECYCLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIFECYCLE)


class UbuntuPackageLifecycleContractTest(unittest.TestCase):
    def test_windows_is_an_explicit_manual_release_blocker(self) -> None:
        self.assertTrue(LIFECYCLE.WINDOWS_MANUAL_BLOCKER["release_blocker"])
        self.assertEqual(LIFECYCLE.WINDOWS_MANUAL_BLOCKER["automation"], "not-run")
        self.assertIn("failed-upgrade recovery", LIFECYCLE.WINDOWS_MANUAL_BLOCKER["required_manual_checks"])

    def test_lifecycle_runs_offline_after_controlled_preparation(self) -> None:
        source = LIFECYCLE.Path(LIFECYCLE.__file__).read_text(encoding="utf-8")
        self.assertIn('"--network", "none"', source)
        self.assertIn('"--security-opt=seccomp=unconfined"', source)
        self.assertIn('"xvfb"', source)
        self.assertIn("Xvfb :99", source)
        self.assertIn("--no-remote --marionette", source)
        self.assertIn("m12-created-profile/.parentlock", source)
        self.assertIn("--createprofile", source)
        self.assertIn("controlled dependency fetch only", source)
        self.assertIn('"automatic_rollback": "not claimed"', source)

    def test_test_fixtures_are_not_release_versions(self) -> None:
        self.assertIn("never a release asset", LIFECYCLE.make_fixture.__doc__ or "")
        self.assertEqual(LIFECYCLE.PACKAGE, "goodbear-browser")


if __name__ == "__main__":
    unittest.main()
