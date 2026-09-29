#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m2_01_probe", ROOT / "tools" / "run_m2_01_verification_probe.py"
)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class M201VerificationProbeRunnerTest(unittest.TestCase):
    def test_runs_the_two_focused_upstream_psm_tests(self) -> None:
        self.assertEqual(
            PROBE.UPSTREAM_TESTS,
            (
                "security/manager/ssl/tests/unit/test_self_signed_certs.js",
                "security/manager/ssl/tests/unit/test_cert_overrides.js",
            ),
        )

    def test_docker_probe_is_fail_closed_and_offline(self) -> None:
        command = PROBE.docker_command("goodbear-probe:test", PROBE.UPSTREAM_TESTS[0])
        self.assertIn("--network", command)
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertIn("--cap-drop", command)
        self.assertEqual(command[command.index("--cap-drop") + 1], "ALL")
        self.assertIn("no-new-privileges", command)
        self.assertIn("PIP_NO_INDEX=1", command)
        self.assertEqual(
            command[-3:], ["./mach", "xpcshell-test", PROBE.UPSTREAM_TESTS[0]]
        )

        source_mount = next(
            entry for entry in command if f"dst={PROBE.CANDIDATE.CONTAINER_SOURCE}" in entry
        )
        self.assertTrue(source_mount.endswith(",readonly"))


if __name__ == "__main__":
    unittest.main()
