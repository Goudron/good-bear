#!/usr/bin/env python3
"""Focused no-VM tests for the GB100-M15-03 local KVM preflight plan."""

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
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import plan_m15_03_local_kvm as KVM  # noqa: E402


class M1503LocalKvmPlanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads((ROOT / "config" / "m15-03-windows-autounattend-lock.json").read_text(encoding="utf-8"))
        self.contract = KVM.load_contract()
        # The renderer's storage calculation is unit-tested below.  The
        # structural plan tests must not depend on spare capacity of the
        # developer workstation (or allocate any of the proposed raw disk).
        free_space = SimpleNamespace(f_bavail=100 * KVM.GIB, f_frsize=1)
        statvfs = mock.patch.object(KVM.os, "statvfs", return_value=free_space)
        statvfs.start()
        self.addCleanup(statvfs.stop)

    def test_contract_pins_small_headless_sata_uefi_preflight_only_machine(self) -> None:
        self.assertEqual(self.contract["vm"]["vcpus"], 2)
        self.assertEqual(self.contract["vm"]["memory_mib"], 2560)
        self.assertFalse(self.contract["vm"]["graphics"])
        self.assertTrue(self.contract["firmware"]["uefi"])
        self.assertTrue(self.contract["firmware"]["secure_boot"])
        self.assertEqual(self.contract["disk"], {
            "format": "raw", "bus": "sata", "logical_size_gib": 250,
            "initial_allocation_reservation_gib": 64, "minimum_free_headroom_gib": 16,
        })
        self.assertFalse(self.contract["media"]["virtio_windowspe_load"])
        self.assertTrue(self.contract["media"]["virtio_read_only"])
        self.assertEqual(self.contract["network"]["model"], "e1000e")
        self.assertFalse(any(self.contract["lifecycle"].values()))

    def test_rendered_xml_has_no_gui_or_virtio_windowspe_path_and_all_media_are_read_only_sata(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            plan, xml = self._make_plan(Path(temporary))
        self.assertIn('<loader readonly="yes" secure="yes" type="pflash">', xml)
        self.assertNotIn('<graphics', xml)
        self.assertIn('<serial type="pty">', xml)
        self.assertIn('target dev="sda" bus="sata"', xml)
        self.assertIn('target dev="sdb" bus="sata"/><readonly/>', xml)
        self.assertIn('target dev="sdc" bus="sata"/><readonly/>', xml)
        self.assertIn('target dev="sdd" bus="sata"/><readonly/>', xml)
        self.assertIn('<model type="e1000e"/>', xml)
        self.assertNotIn('bus="virtio"', xml)
        self.assertNotIn('<graphics type="vnc"', xml)
        self.assertFalse(plan["media"]["virtio_iso"]["trusted"])
        self.assertTrue(plan["media"]["virtio_iso"]["post_boot_signtool_kp_gate_required"])
        self.assertFalse(plan["media"]["virtio_iso"]["loaded_in_windowspe"])

    def test_sparse_disk_budget_does_not_require_250_gib_upfront_but_reserves_safe_real_capacity(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            plan, _ = self._make_plan(Path(temporary))
        disk = plan["disk"]
        self.assertEqual(disk["logical_raw_disk_bytes"], 250 * KVM.GIB)
        self.assertEqual(disk["planned_initial_allocated_bytes"], 0)
        self.assertEqual(disk["initial_allocation_reservation_bytes"], 64 * KVM.GIB)
        self.assertEqual(disk["minimum_free_headroom_bytes"], 16 * KVM.GIB)
        self.assertTrue(disk["safe_without_full_preallocation"])

    def test_existing_raw_disk_or_symlinked_input_is_rejected_before_any_plan(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            root = Path(temporary)
            vm_output, config_iso, virtio, lock = self._inputs(root)
            (vm_output / "goodbear-m15-03-windows-server-2025-prep.raw").write_bytes(b"old")
            with self.assertRaisesRegex(KVM.KvmPlanError, "reuse or overwrite"):
                KVM.make_plan(lock, self.contract, vm_output_dir=vm_output, configuration_set=config_iso, virtio_iso=virtio)
            (vm_output / "goodbear-m15-03-windows-server-2025-prep.raw").unlink()
            real = root / "real-virtio.iso"
            real.write_bytes(b"virtio")
            virtio.unlink()
            virtio.symlink_to(real)
            with self.assertRaisesRegex(KVM.KvmPlanError, "regular non-symlink"):
                KVM.make_plan(lock, self.contract, vm_output_dir=vm_output, configuration_set=config_iso, virtio_iso=virtio)

    def test_configuration_set_integrity_and_no_remaster_declaration_are_mandatory(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            root = Path(temporary)
            vm_output, config_iso, virtio, lock = self._inputs(root)
            assembly_path = config_iso.parent / "assembly.json"
            assembly = json.loads(assembly_path.read_text(encoding="utf-8"))
            assembly["windows_iso_remastered"] = True
            assembly_path.write_text(json.dumps(assembly), encoding="utf-8")
            with self.assertRaisesRegex(KVM.KvmPlanError, "remastered"):
                KVM.make_plan(lock, self.contract, vm_output_dir=vm_output, configuration_set=config_iso, virtio_iso=virtio)

    def test_plan_write_is_atomic_project_artifact_only(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            plan, xml = self._make_plan(Path(temporary))
            destination = ROOT / "build" / f"m15-03-local-kvm-plan-test-{uuid.uuid4().hex}"
            try:
                result = KVM.write_plan(destination, plan, xml)
                self.assertTrue((result / KVM.PLAN_NAME).is_file())
                self.assertTrue((result / KVM.DOMAIN_NAME).is_file())
                loaded = json.loads((result / KVM.PLAN_NAME).read_text(encoding="utf-8"))
                self.assertFalse(loaded["lifecycle"]["vm_create"])
                self.assertFalse(loaded["lifecycle"]["disk_create"])
                self.assertFalse(loaded["lifecycle"]["libvirt_define"])
            finally:
                shutil.rmtree(destination, ignore_errors=True)

    def _make_plan(self, root: Path) -> tuple[dict, str]:
        vm_output, config_iso, virtio, lock = self._inputs(root)
        return KVM.make_plan(lock, self.contract, vm_output_dir=vm_output, configuration_set=config_iso, virtio_iso=virtio)

    def _inputs(self, root: Path) -> tuple[Path, Path, Path, dict]:
        vm_output = root / "vm-output"
        vm_output.mkdir()
        windows = root / "windows.iso"
        windows.write_bytes(b"windows")
        lock = copy.deepcopy(self.lock)
        lock["inputs"]["windows_server_2025_eval_iso"]["path"] = str(windows)
        lock["inputs"]["windows_server_2025_eval_iso"]["sha256"] = hashlib.sha256(windows.read_bytes()).hexdigest()
        config_dir = root / "configuration-set"
        config_dir.mkdir()
        config_iso = config_dir / KVM.CONFIG_SET.ISO_NAME
        config_iso.write_bytes(b"configuration-set")
        (config_dir / "assembly.json").write_text(json.dumps({
            "iso": {"path": KVM.CONFIG_SET.ISO_NAME, "sha256": hashlib.sha256(config_iso.read_bytes()).hexdigest()},
            "windows_iso_remastered": False, "virtio_promoted": False, "sensitive_material_absent": True,
        }), encoding="utf-8")
        virtio = root / "virtio.iso"
        virtio.write_bytes(b"virtio")
        return vm_output, config_iso, virtio, lock


if __name__ == "__main__":
    unittest.main()
