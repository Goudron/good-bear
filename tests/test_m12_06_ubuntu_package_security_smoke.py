#!/usr/bin/env python3
"""Focused contracts for GB100-M12-06 Ubuntu package security smoke."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m12_06", ROOT / "tools" / "run_m12_06_ubuntu_package_security_smoke.py"
)
assert SPEC and SPEC.loader
M12_06 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M12_06
SPEC.loader.exec_module(M12_06)


class UbuntuPackageSecuritySmokeContractTest(unittest.TestCase):
    def test_windows_is_explicitly_manual_and_blocks_public_release(self) -> None:
        self.assertEqual(M12_06.WINDOWS_MANUAL_BLOCKER["automation"], "not-run")
        self.assertTrue(M12_06.WINDOWS_MANUAL_BLOCKER["release_blocker"])
        self.assertIn("uninstall", M12_06.WINDOWS_MANUAL_BLOCKER["required_manual_checks"])

    def test_network_trace_rejects_background_inet_connects(self) -> None:
        self.assertEqual(M12_06.inet_connects("connect(3, {sa_family=AF_UNIX}, 110) = 0"), [])
        self.assertEqual(
            M12_06.inet_connects("socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP) = 3"),
            ["socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP) = 3"],
        )
        self.assertEqual(
            M12_06.inet_connects("connect(4, {sa_family=AF_INET, sin_port=htons(443)}, 16) = 0"),
            ["connect(4, {sa_family=AF_INET, sin_port=htons(443)}, 16) = 0"],
        )

    def test_runner_keeps_the_offline_and_controlled_live_boundaries_distinct(self) -> None:
        source = Path(M12_06.__file__).read_text(encoding="utf-8")
        self.assertIn('"--network", "none"', source)
        self.assertIn('"--network", "host"', source)
        self.assertIn("controlled user-initiated live navigation", source)
        self.assertIn("--security-opt=no-new-privileges:true", source)
        self.assertIn("--security-opt=seccomp=unconfined", source)
        self.assertIn("strace", source)
        self.assertIn("RussianPKI", source)
        self.assertIn("Seccomp", source)
        self.assertIn("http://127.0.0.1:18080/m12-06-offline.html", source)
        self.assertIn("python3 -m http.server 18080 --bind 127.0.0.1", source)
        self.assertIn('" -isForBrowser "', source)
        self.assertIn('endswith(" tab")', source)
        self.assertIn("ptrace would alter Firefox seccomp", source)
        self.assertIn("assert_goodbear_network_boundary", source)

    def test_security_failure_records_quarantine_without_deleting_evidence(self) -> None:
        source = Path(M12_06.__file__).read_text(encoding="utf-8")
        self.assertIn("record_quarantine", source)
        self.assertIn("security-failure.json", source)
        self.assertIn("does not delete a previously promoted\ncandidate", source)


if __name__ == "__main__":
    unittest.main()
