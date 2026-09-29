#!/usr/bin/env python3
"""Focused, pre-VM checks for the GB100-M15-03 configuration-set medium."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import generate_m15_03_autounattend as AUTO  # noqa: E402
import generate_m15_03_configuration_set as CONFIG_SET  # noqa: E402


class M1503ConfigurationSetTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads((ROOT / "config" / "m15-03-windows-autounattend-lock.json").read_text(encoding="utf-8"))

    def test_payload_is_a_configuration_set_not_a_remastered_windows_or_virtio_medium(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload"
            manifest, files = CONFIG_SET.stage_payload(self._pinned_lock(root), payload)
            answer = (payload / "Autounattend.xml").read_text(encoding="utf-8")
            bootstrap = (payload / "$OEM$" / "$1" / "GoodBear" / "first-boot.ps1").read_text(encoding="utf-8")
            self.assertIn("<UseConfigurationSet>true</UseConfigurationSet>", answer)
            self.assertNotIn("PnpCustomizationsWinPE", answer)
            self.assertNotIn("E:\\", answer)
            self.assertIn("Find-VerifiedVirtioMediaDrive", bootstrap)
            self.assertIn("virtio-win-0.1.302", bootstrap)
            self.assertTrue((payload / "$OEM$" / "$$" / "Setup" / "Scripts" / "SetupComplete.cmd").is_file())
            self.assertTrue((payload / "$OEM$" / "$1" / "GoodBear" / "input-cache" / "cloudbase_init.bin").is_file())
            names = {item["path"] for item in manifest["files"]}
            self.assertNotIn("/virtio-win.iso", names)
            self.assertIn("/$OEM$/$1/GoodBear/verify-virtio-signatures.ps1", names)
            self.assertEqual(manifest["virtio"]["included"], False)
            self.assertTrue(all(path.is_file() and not path.is_symlink() for path in files))

    def test_promoted_or_path_pinned_virtio_is_rejected(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["inputs"]["virtio_win"]["path"] = "/tmp/virtio-win.iso"
        changed["inputs"]["virtio_win"]["sha256"] = "a" * 64
        changed["inputs"]["virtio_win"]["signature_verified"] = True
        with self.assertRaisesRegex(Exception, "VirtIO must remain an untrusted"):
            AUTO.validate_lock(changed, verify_files=False)

    def test_symlinked_cloudbase_rejects_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            changed = self._pinned_lock(root)
            real = root / "real.bin"
            real.write_bytes(b"cloudbase")
            linked = root / "linked.bin"
            linked.symlink_to(real)
            changed["inputs"]["cloudbase_init"]["path"] = str(linked)
            changed["inputs"]["cloudbase_init"]["sha256"] = hashlib.sha256(real.read_bytes()).hexdigest()
            destination = ROOT / "build" / f"m15-03-configuration-set-rejected-{uuid.uuid4().hex}"
            with self.assertRaisesRegex(Exception, "not a regular file"):
                CONFIG_SET.assemble(changed, destination)
            self.assertFalse(destination.exists())

    def test_assemble_creates_atomic_inspectable_iso_and_nonsecret_assembly_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = ROOT / "build" / f"m15-03-configuration-set-test-{uuid.uuid4().hex}"
            try:
                result = CONFIG_SET.assemble(self._pinned_lock(root), destination)
                self.assertEqual(result, destination.resolve())
                iso = result / CONFIG_SET.ISO_NAME
                assembly = json.loads((result / "assembly.json").read_text(encoding="utf-8"))
                self.assertTrue(iso.is_file())
                self.assertEqual(assembly["iso"]["sha256"], hashlib.sha256(iso.read_bytes()).hexdigest())
                self.assertFalse(assembly["windows_iso_remastered"])
                self.assertFalse(assembly["virtio_promoted"])
                CONFIG_SET.verify_iso_tree(CONFIG_SET.require_iso_builder(), iso)
            finally:
                shutil.rmtree(destination, ignore_errors=True)

    def _pinned_lock(self, root: Path) -> dict:
        changed = copy.deepcopy(self.lock)
        for index, name in enumerate(("windows_server_2025_eval_iso", "cloudbase_init"), 1):
            source = root / f"{name}.bin"
            source.write_bytes(f"input-{index}".encode())
            changed["inputs"][name]["path"] = str(source)
            changed["inputs"][name]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        changed["inputs"]["cloudbase_init"]["publisher"] = "Cloudbase Solutions"
        return changed


if __name__ == "__main__":
    unittest.main()
