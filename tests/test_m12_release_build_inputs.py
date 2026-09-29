#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))
from host_build_context import SOURCE

SPEC = importlib.util.spec_from_file_location("m12_inputs", ROOT / "tools" / "prepare_m12_release_build_inputs.py")
assert SPEC and SPEC.loader
INPUTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INPUTS)


class ReleaseBuildInputsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = INPUTS.load_lock(ROOT / "config" / "m12-release-build-inputs-lock.json")

    def test_repository_lock_pins_independent_targets_and_non_lto_mode(self) -> None:
        self.assertEqual(set(self.lock["platforms"]), {"ubuntu-amd64", "windows-x64"})
        self.assertEqual(self.lock["release_locale"], "ru")
        ubuntu = self.lock["platforms"]["ubuntu-amd64"]
        self.assertEqual(ubuntu["target"], "Ubuntu 26.04 amd64")
        self.assertEqual(ubuntu["libc6_minimum"], "2.43")
        self.assertIn("must not claim Ubuntu 24.04 compatibility", ubuntu["target_rationale"])
        self.assertEqual(self.lock["intermediate_candidate"]["lto"], "forbidden")
        self.assertEqual(self.lock["network_policy"]["build_after_fetch"], "network forbidden")
        self.assertEqual(len(self.lock["platforms"]["windows-x64"]["toolchain"]["sha256"]), 64)

    def test_rejects_lto_or_networked_intermediate_candidate(self) -> None:
        for field, value in (("lto", "enabled"),):
            changed = copy.deepcopy(self.lock)
            changed["intermediate_candidate"][field] = value
            with self.assertRaisesRegex(INPUTS.BuildInputError, "forbid LTO"):
                self._validate(changed)
        changed = copy.deepcopy(self.lock)
        changed["network_policy"]["build_after_fetch"] = "allowed"
        with self.assertRaisesRegex(INPUTS.BuildInputError, "network"):
            self._validate(changed)

    def test_stage_then_verify_is_atomic_and_hash_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "inputs"
            promoted = INPUTS.stage(self.lock, destination)
            self.assertTrue(promoted.is_dir())
            INPUTS.verify_snapshot(self.lock, promoted)
            with self.assertRaisesRegex(INPUTS.BuildInputError, "refusing to replace"):
                INPUTS.stage(self.lock, destination)

    def test_tampered_source_never_promotes_and_stays_quarantined(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["platforms"]["ubuntu-amd64"]["inputs"][0]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "inputs"
            with self.assertRaisesRegex(INPUTS.BuildInputError, "hash mismatch"):
                INPUTS.stage(changed, destination)
            self.assertFalse((destination / "ubuntu-amd64").exists())
            self.assertTrue(any((destination / "quarantine").iterdir()))

    def test_windows_lock_records_the_verified_native_vm_inputs(self) -> None:
        windows = self.lock["platforms"]["windows-x64"]
        self.assertEqual(windows["vm_input"]["status"], "cached-and-sha256-verified")
        self.assertEqual(windows["execution_status"], "ready-for-local-windows-build")
        evidence = windows["native_vm_toolchain_evidence"]
        self.assertEqual(evidence["offline_cache"]["file_count"], 918)
        self.assertEqual(len(evidence["llvm_archive"]["sha256"]), 64)

    def test_windows_installer_owner_pins_match_the_current_source(self) -> None:
        owners = self.lock["platforms"]["windows-x64"]["installer"]["source_owner_pins"]
        for owner in owners:
            with self.subTest(owner=owner["path"]):
                self.assertEqual(INPUTS.sha256_file(SOURCE / owner["path"]), owner["sha256"])

    def _validate(self, lock: dict) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            INPUTS.load_lock(path)


if __name__ == "__main__":
    unittest.main()
