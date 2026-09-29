#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m2_02_probe", ROOT / "tools" / "run_m2_02_container_navigation_probe.py"
)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class M202ContainerNavigationProbeRunnerTest(unittest.TestCase):
    def test_runs_the_focused_upstream_probes(self) -> None:
        self.assertEqual(PROBE.XPCSHELL_TESTS, ("caps/tests/unit/test_origin.js",))
        self.assertEqual(
            PROBE.BROWSER_TESTS,
            (
                "browser/components/contextualidentity/test/browser/browser_usercontext.js",
                "browser/components/contextualidentity/test/browser/browser_reopenIn.js",
                "browser/base/content/test/referrer/browser_referrer_open_link_in_container_tab.js",
                "browser/components/contextualidentity/test/browser/browser_windowOpen.js",
                "browser/components/sessionstore/test/browser_restoreTabContainer.js",
            ),
        )

    def test_docker_probes_are_fail_closed_and_offline(self) -> None:
        for suite, test in (
            ("xpcshell", PROBE.XPCSHELL_TESTS[0]),
            ("browser", PROBE.BROWSER_TESTS[0]),
        ):
            command = PROBE.docker_command("goodbear-probe:test", suite, test)
            self.assertEqual(command[command.index("--network") + 1], "none")
            self.assertEqual(command[command.index("--cap-drop") + 1], "ALL")
            self.assertIn("no-new-privileges", command)
            self.assertIn("PIP_NO_INDEX=1", command)

            source_mount = next(
                entry
                for entry in command
                if f"dst={PROBE.CANDIDATE.CONTAINER_SOURCE}" in entry
            )
            self.assertTrue(source_mount.endswith(",readonly"))

    def test_browser_probe_is_headless_and_suite_name_is_validated(self) -> None:
        command = PROBE.docker_command(
            "goodbear-probe:test", "browser", PROBE.BROWSER_TESTS[0]
        )
        self.assertEqual(
            command[-4:],
            ["./mach", "mochitest", "--headless", PROBE.BROWSER_TESTS[0]],
        )
        with self.assertRaisesRegex(ValueError, "unsupported test suite"):
            PROBE.docker_command("goodbear-probe:test", "unknown", "test.js")


if __name__ == "__main__":
    unittest.main()
