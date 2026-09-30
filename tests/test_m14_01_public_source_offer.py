#!/usr/bin/env python3
"""Focused contracts for the GB100-M14-01 public source offer."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m14_01_public_source_offer", ROOT / "tools/verify_public_source_offer.py")
assert SPEC and SPEC.loader
OFFER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = OFFER
SPEC.loader.exec_module(OFFER)


class PublicSourceOfferTest(unittest.TestCase):
    def setUp(self) -> None:
        self.report = OFFER.validate(ROOT)
        self.inventory = OFFER.load_inventory(ROOT)
        self.allowlist = self.inventory["corresponding_source"]["source_offer"]["public_repository"][
            "tracked_path_allowlist"
        ]

    def test_current_index_is_a_declared_source_offer(self) -> None:
        self.assertEqual(self.report["task"], "GB100-M14-01")
        self.assertEqual(self.report["full_firefox_source_mirror"], "forbidden")
        self.assertGreater(self.report["checked_indexed_paths"], 0)

    def test_rejects_firefox_copies_outputs_secrets_and_undeclared_files(self) -> None:
        cases = {
            "source/worktrees/firefox-156.0/browser/moz.build": "Firefox source",
            "artifacts/release/goodbear-browser_1.0.deb": "candidate",
            "obj-goodbear/dist/browser/omni.ja": "object",
            "profiles/default/cookies.sqlite": "profile",
            "release/private-signing.key": "private key",
            "unreviewed-file.txt": "undeclared",
        }
        for path, description in cases.items():
            with self.subTest(description=description):
                with self.assertRaises(OFFER.PublicSourceOfferError):
                    OFFER.validate_paths([path], self.allowlist)

    def test_accepts_declared_source_not_local_build_state(self) -> None:
        OFFER.validate_paths([
            "patches/series",
            "build/windows/mozconfig.release-lto",
            "artwork/final/m10-03/goodbear-welcome.png",
            "artifacts/.gitkeep",
            "source/.gitkeep",
            "README.md",
        ], self.allowlist)

    def test_recovery_contracts_never_reconfigure_or_relink(self) -> None:
        paths = self.inventory["corresponding_source"]["source_offer"]["native_build_paths"]
        self.assertEqual(paths["windows_x64"]["installer_only_recovery"], "./mach build installers-ru")
        self.assertEqual(paths["windows_x64"]["recovery_forbidden_commands"],
                         ["./mach configure", "./mach build"])
        self.assertEqual(paths["ubuntu_amd64"]["package_only_recovery"],
                         "tools/build_m13_06_ubuntu_deb.py")
        self.assertEqual(paths["ubuntu_amd64"]["recovery_forbidden_commands"],
                         ["mach configure", "mach build"])


if __name__ == "__main__":
    unittest.main()
