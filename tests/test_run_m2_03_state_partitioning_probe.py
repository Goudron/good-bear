#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m2_03_probe", ROOT / "tools/run_m2_03_state_partitioning_probe.py"
)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROBE
SPEC.loader.exec_module(PROBE)


class RunM203StatePartitioningProbeTest(unittest.TestCase):
    def test_probe_set_covers_every_classification_owner(self) -> None:
        self.assertEqual(len(PROBE.XPCSHELL_TESTS), 6)
        self.assertEqual(len(PROBE.BROWSER_TESTS), 3)
        all_tests = set(PROBE.XPCSHELL_TESTS + PROBE.BROWSER_TESTS)
        for expected in (
            "toolkit/components/passwordmgr/test/unit/test_LoginManagerParent_getGeneratedPassword.js",
            "security/manager/ssl/tests/unit/test_client_auth_remember_service_read.js",
            "security/manager/ssl/tests/unit/test_session_resumption.js",
            "netwerk/test/unit/test_cache_jar.js",
            "netwerk/test/unit/test_separate_connections.js",
            "netwerk/test/unit/test_retry_0rtt.js",
            "dom/serviceworkers/test/browser_unregister_with_containers.js",
            "browser/components/contextualidentity/test/browser/browser_usercontextid_new_window.js",
            "browser/components/contextualidentity/test/browser/browser_forgetaboutsite.js",
        ):
            self.assertIn(expected, all_tests)

    def test_xpcshell_command_is_offline_unprivileged_and_source_read_only(self) -> None:
        test = PROBE.XPCSHELL_TESTS[0]
        command = PROBE.docker_command("goodbear-test", "xpcshell", test)
        self.assertEqual(command[:3], ["docker", "run", "--rm"])
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertEqual(command[command.index("--cap-drop") + 1], "ALL")
        self.assertEqual(
            command[command.index("--security-opt") + 1], "no-new-privileges"
        )
        self.assertEqual(command[command.index("--user") + 1], "1000:1000")
        mounts = [
            command[index + 1]
            for index, argument in enumerate(command)
            if argument == "--mount"
        ]
        source_mount = next(
            mount
            for mount in mounts
            if f"dst={PROBE.CANDIDATE.CONTAINER_SOURCE}" in mount
        )
        self.assertIn("readonly", source_mount)
        self.assertEqual(command[-3:], ["./mach", "xpcshell-test", test])

    def test_browser_command_is_headless_and_rejects_unknown_suites(self) -> None:
        test = PROBE.BROWSER_TESTS[0]
        command = PROBE.docker_command("goodbear-test", "browser", test)
        self.assertEqual(command[-4:], ["./mach", "mochitest", "--headless", test])
        with self.assertRaisesRegex(ValueError, "unsupported test suite"):
            PROBE.docker_command("goodbear-test", "unknown", test)


if __name__ == "__main__":
    unittest.main()
