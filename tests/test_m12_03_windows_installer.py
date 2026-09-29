#!/usr/bin/env python3
"""Focused fail-closed contracts for GB100-M12-03 Windows packaging."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("m12_03", ROOT / "tools" / "build_m12_03_windows_installer.py")
assert SPEC and SPEC.loader
WINDOWS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WINDOWS)


class WindowsInstallerContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = WINDOWS.load_contract()

    def test_pins_the_supported_russian_nsis_full_installer_without_msi_or_msix_claim(self) -> None:
        installer = self.lock["platforms"]["windows-x64"]["installer"]
        self.assertEqual(installer["format"], "NSIS full offline installer (.exe)")
        self.assertEqual(installer["architecture"], "x64")
        self.assertEqual(installer["release_locale"], "ru")
        self.assertEqual(installer["filename"], "GoodBear Setup 1.0 x64 ru.exe")
        self.assertEqual(installer["build_steps"][-1], ["./mach", "build", "installers-ru"])

    def test_source_owner_pins_match_the_reviewed_tree(self) -> None:
        WINDOWS.verify_source_owners(self.lock)

    def test_nsis_wizard_branding_is_a_required_packaging_preflight(self) -> None:
        WINDOWS.verify_nsis_branding_assets()

    def test_failed_nsis_wizard_branding_blocks_before_host_or_build_steps(self) -> None:
        with mock.patch.object(WINDOWS.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
            with self.assertRaisesRegex(WINDOWS.WindowsInstallerError, "wizard branding assets"):
                WINDOWS.preflight(self.lock)

    def test_unsigned_or_unavailable_windows_inputs_fail_closed_before_a_build(self) -> None:
        unavailable = copy.deepcopy(self.lock)
        vm_input = unavailable["platforms"]["windows-x64"]["vm_input"]
        vm_input["status"] = "not-cached"
        vm_input["required_before_execution"] = ["Windows SDK"]
        with self.assertRaisesRegex(WINDOWS.WindowsInstallerError, "cached and SHA-256-verified"):
            WINDOWS.require_ready_windows_inputs(unavailable)
        self.assertEqual(self.lock["platforms"]["windows-x64"]["installer"]["code_signing"]["candidate"],
                         "unsigned local candidate only")
        self.assertIn("blocked", self.lock["platforms"]["windows-x64"]["installer"]["code_signing"]["public_release"])

    def test_rejects_locale_format_and_invented_signing_trust_drift(self) -> None:
        cases = (
            ("format", "MSIX"),
            ("release_locale", "en-US"),
        )
        for field, value in cases:
            changed = copy.deepcopy(self.lock)
            changed["platforms"]["windows-x64"]["installer"][field] = value
            with self.assertRaises(WINDOWS.WindowsInstallerError):
                self._load(changed)
        changed = copy.deepcopy(self.lock)
        changed["platforms"]["windows-x64"]["installer"]["code_signing"]["self_signed_or_invented_trust"] = "allowed"
        with self.assertRaisesRegex(WINDOWS.WindowsInstallerError, "invented"):
            self._load(changed)

    def _load(self, lock: dict) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "m12-lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            WINDOWS.load_contract(path)


if __name__ == "__main__":
    unittest.main()
