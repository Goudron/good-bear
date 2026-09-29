#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m2_04_probe", ROOT / "tools" / "run_m2_04_trust_domain_probe.py"
)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class M204TrustDomainProbeRunnerTest(unittest.TestCase):
    def test_docker_probe_is_offline_unprivileged_and_source_read_only(self) -> None:
        command = PROBE.docker_command(
            "goodbear-ubuntu-m1-06:local",
            ["gtest", "psm_GoodBearTrustDomain.*"],
        )
        rendered = " ".join(command)
        self.assertIn("--network none", rendered)
        self.assertIn("--cap-drop ALL", rendered)
        self.assertIn("--security-opt no-new-privileges", rendered)
        self.assertIn("--user 1000:1000", rendered)
        self.assertIn("PIP_NO_INDEX=1", rendered)
        self.assertIn("./mach gtest psm_GoodBearTrustDomain.*", rendered)

        source_mount = next(
            command[index + 1]
            for index, item in enumerate(command[:-1])
            if item == "--mount"
            and f"dst={PROBE.CANDIDATE.CONTAINER_SOURCE}" in command[index + 1]
        )
        self.assertIn("readonly", source_mount)

    def test_probe_set_is_narrow_and_has_positive_ui_evidence(self) -> None:
        gtest = PROBE.docker_command("image", ["gtest", "psm_GoodBearTrustDomain.*"])
        ui = PROBE.docker_command(
            "image",
            [
                "mochitest",
                "--headless",
                "browser/base/content/test/siteIdentity/browser_getSecurityInfo.js",
            ],
        )
        self.assertEqual(gtest[-2:], ["gtest", "psm_GoodBearTrustDomain.*"])
        self.assertEqual(
            ui[-3:],
            [
                "mochitest",
                "--headless",
                "browser/base/content/test/siteIdentity/browser_getSecurityInfo.js",
            ],
        )


if __name__ == "__main__":
    unittest.main()
