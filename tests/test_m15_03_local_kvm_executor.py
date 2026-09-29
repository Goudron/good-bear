#!/usr/bin/env python3
"""Structural and mocked-command tests for the M15-03 KVM executor."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import execute_m15_03_local_kvm as EXEC  # noqa: E402
import plan_m15_03_local_kvm as KVM  # noqa: E402
import generate_m15_03_autounattend as AUTO  # noqa: E402


class M1503LocalKvmExecutorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads((ROOT / "config" / "m15-03-windows-autounattend-lock.json").read_text(encoding="utf-8"))
        self.contract = KVM.load_contract()
        # The executor tests exercise only a mocked command path.  Keep the
        # preflight's capacity branch deterministic instead of making it
        # depend on free space on the workstation that runs the tests.
        free_space = SimpleNamespace(f_bavail=100 * KVM.GIB, f_frsize=1)
        statvfs = mock.patch.object(KVM.os, "statvfs", return_value=free_space)
        statvfs.start()
        self.addCleanup(statvfs.stop)

    def test_validate_rederives_exact_secure_plan_and_never_mutates(self) -> None:
        with self._reviewed_plan() as fixture:
            before = sorted(item.name for item in fixture["output"].iterdir())
            evidence = EXEC.validate_plan(fixture["plan_dir"])
            after = sorted(item.name for item in fixture["output"].iterdir())
        self.assertEqual(before, after)
        self.assertEqual(evidence["domain_name"], EXEC.EXPECTED_DOMAIN)
        self.assertTrue(evidence["virtio_untrusted_until_guest_signtool_kp_gate"])

    def test_tampered_xml_or_existing_raw_is_rejected_before_commands(self) -> None:
        with self._reviewed_plan() as fixture:
            xml = fixture["plan_dir"] / KVM.DOMAIN_NAME
            xml.write_text("<domain/>", encoding="utf-8")
            with self.assertRaisesRegex(EXEC.KvmExecutionError, "differs"):
                EXEC.validate_plan(fixture["plan_dir"])
        with self._reviewed_plan() as fixture:
            (fixture["output"] / f"{EXEC.EXPECTED_DOMAIN}.raw").write_bytes(b"old")
            with self.assertRaisesRegex(EXEC.KvmExecutionError, "reuse"):
                EXEC.validate_plan(fixture["plan_dir"])

    def test_dry_run_command_sequence_is_fixed_sg_virsh_and_never_starts_network(self) -> None:
        with self._reviewed_plan() as fixture:
            evidence = EXEC.validate_plan(fixture["plan_dir"])
        commands = EXEC.command_sequence(evidence)
        self.assertEqual(len(commands), 6)
        for command in commands:
            self.assertEqual(command[:3], ["sg", "libvirt", "-c"])
            self.assertIn("virsh -c qemu:///system", command[3])
        self.assertIn("net-info default", commands[0][3])
        self.assertNotIn("net-start", " ".join(part for command in commands for part in command))
        self.assertNotIn("sudo", " ".join(part for command in commands for part in command))

    def test_create_uses_only_exact_preflight_then_define_start_and_sparse_files(self) -> None:
        with self._reviewed_plan() as fixture:
            evidence = EXEC.validate_plan(fixture["plan_dir"])
            commands: list[list[str]] = []
            responses = iter([
                (0, "Name: default\nActive: yes\n", ""),
                (0, "\n", ""),
                (0, "", ""),  # ACL raw
                (0, "", ""),  # ACL nvram
                (0, "", ""),  # ACL media 1
                (0, "", ""),  # ACL media 2
                (0, "", ""),  # ACL media 3
                (0, "", ""),  # each owned parent; mock counts dynamically below
            ])

            def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
                commands.append(command)
                shell = command[-1] if command[:3] == ["sg", "libvirt", "-c"] else ""
                if "net-info default" in shell:
                    return subprocess.CompletedProcess(command, 0, "Name: default\nActive: yes\n", "")
                if "list --all --name" in shell:
                    return subprocess.CompletedProcess(command, 0, "\n", "")
                if "domstate" in shell:
                    return subprocess.CompletedProcess(command, 0, "running\n", "")
                if "ttyconsole" in shell:
                    return subprocess.CompletedProcess(command, 0, "/dev/pts/42\n", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = EXEC.create(evidence, runner)
            raw = Path(result["raw_disk"])
            nvram = Path(result["nvram"])
            self.assertEqual(raw.stat().st_size, 250 * KVM.GIB)
            self.assertEqual(nvram.stat().st_size, Path(fixture["firmware_vars"]).stat().st_size)
            self.assertEqual(result["domain_state"], "running")
            self.assertEqual(result["serial_console"], "/dev/pts/42")
            sg_shells = [command[3] for command in commands if command[:3] == ["sg", "libvirt", "-c"]]
            self.assertEqual(len(sg_shells), 6)
            self.assertIn("define", sg_shells[2])
            self.assertIn("start", sg_shells[3])
            self.assertFalse(any("net-start" in shell or "destroy" in shell or "undefine" in shell for shell in sg_shells))

    def test_existing_domain_or_inactive_default_network_blocks_before_file_creation(self) -> None:
        with self._reviewed_plan() as fixture:
            evidence = EXEC.validate_plan(fixture["plan_dir"])
            raw = Path(evidence["raw_disk"])

            def existing_domain(command: list[str]) -> subprocess.CompletedProcess[str]:
                shell = command[-1]
                if "net-info default" in shell:
                    return subprocess.CompletedProcess(command, 0, "Active: yes\n", "")
                return subprocess.CompletedProcess(command, 0, EXEC.EXPECTED_DOMAIN + "\n", "")

            with self.assertRaisesRegex(EXEC.KvmExecutionError, "existing domain"):
                EXEC.create(evidence, existing_domain)
            self.assertFalse(raw.exists())

            def inactive_network(command: list[str]) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess(command, 0, "Name: default\nActive: no\n", "")

            with self.assertRaisesRegex(EXEC.KvmExecutionError, "not active"):
                EXEC.create(evidence, inactive_network)
            self.assertFalse(raw.exists())

    def test_boot_automation_create_accepts_only_exact_loopback_derivative(self) -> None:
        with self._reviewed_plan() as fixture:
            evidence = EXEC.validate_plan(fixture["plan_dir"])
            normal = (fixture["plan_dir"] / KVM.DOMAIN_NAME).read_text(encoding="utf-8")
            boot_xml = fixture["plan_dir"] / EXEC.BOOT_AUTOMATION_XML_NAME
            self.assertFalse(boot_xml.exists())
            self.assertEqual(EXEC.write_boot_automation_xml(evidence), boot_xml)
            self.assertEqual(boot_xml.read_text(encoding="utf-8"), EXEC.render_loopback_boot_automation_xml(normal))
            self.assertIn('<input type="keyboard" bus="usb"/>', boot_xml.read_text(encoding="utf-8"))
            with self.assertRaisesRegex(EXEC.KvmExecutionError, "refusing to overwrite"):
                EXEC.write_boot_automation_xml(evidence)
            validated = EXEC.validate_boot_automation_xml(evidence, boot_xml)
            commands: list[list[str]] = []

            def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
                commands.append(command)
                shell = command[-1] if command[:3] == ["sg", "libvirt", "-c"] else ""
                if "net-info default" in shell:
                    return subprocess.CompletedProcess(command, 0, "Name: default\nActive: yes\n", "")
                if "list --all --name" in shell:
                    return subprocess.CompletedProcess(command, 0, "\n", "")
                if "domstate" in shell:
                    return subprocess.CompletedProcess(command, 0, "running\n", "")
                if "ttyconsole" in shell:
                    return subprocess.CompletedProcess(command, 0, "/dev/pts/42\n", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = EXEC.create(evidence, runner, domain_xml=validated, boot_automation=True)
            self.assertTrue(result["temporary_local_loopback_vnc_for_pre_os_boot_automation"])
            defines = [command[3] for command in commands if command[:3] == ["sg", "libvirt", "-c"] and " define " in command[3]]
            self.assertEqual(len(defines), 1)
            self.assertIn(str(boot_xml), defines[0])
            boot_xml.write_text("<domain/>", encoding="utf-8")
            with self.assertRaisesRegex(EXEC.KvmExecutionError, "differs"):
                EXEC.validate_boot_automation_xml(evidence, boot_xml)

    class _PlanFixture:
        def __init__(self, parent: "M1503LocalKvmExecutorTest") -> None:
            self.parent = parent
            self.temp: tempfile.TemporaryDirectory[str] | None = None
            self.values: dict[str, Path] = {}

        def __enter__(self) -> dict[str, Path]:
            self.temp = tempfile.TemporaryDirectory(dir=ROOT / "build")
            root = Path(self.temp.name)
            output_name = f"m15-03-local-vm-test-executor-{os.urandom(4).hex()}"
            output = ROOT / "build" / output_name
            output.mkdir()
            windows = root / "windows.iso"; windows.write_bytes(b"windows")
            lock = copy.deepcopy(self.parent.lock)
            lock["inputs"]["windows_server_2025_eval_iso"]["path"] = str(windows)
            lock["inputs"]["windows_server_2025_eval_iso"]["sha256"] = hashlib.sha256(windows.read_bytes()).hexdigest()
            config_dir = root / "configuration-set"; config_dir.mkdir()
            config = config_dir / KVM.CONFIG_SET.ISO_NAME; config.write_bytes(b"configuration-set")
            (config_dir / "assembly.json").write_text(json.dumps({
                "iso": {"path": KVM.CONFIG_SET.ISO_NAME, "sha256": hashlib.sha256(config.read_bytes()).hexdigest()},
                "windows_iso_remastered": False, "virtio_promoted": False, "sensitive_material_absent": True,
            }), encoding="utf-8")
            virtio = root / "virtio.iso"; virtio.write_bytes(b"virtio")
            firmware_code = root / "code.fd"; firmware_code.write_bytes(b"code")
            firmware_vars = root / "vars.fd"; firmware_vars.write_bytes(b"vars")
            contract = copy.deepcopy(self.parent.contract)
            contract["firmware"]["code_candidates"] = [str(firmware_code)]
            contract["firmware"]["vars_template_candidates"] = [str(firmware_vars)]
            plan, xml = KVM.make_plan(lock, contract, vm_output_dir=output, configuration_set=config, virtio_iso=virtio)
            plan_dir = ROOT / "build" / f"m15-03-local-kvm-plan-test-executor-{os.urandom(4).hex()}"
            plan_dir.mkdir()
            (plan_dir / KVM.PLAN_NAME).write_text(json.dumps(plan), encoding="utf-8")
            (plan_dir / KVM.DOMAIN_NAME).write_text(xml, encoding="utf-8")
            # The executor loads current defaults, so replace the two narrowly
            # scoped loaders for this fixture lifetime.
            self.patchers = [
                mock.patch.object(AUTO, "load_lock", return_value=lock),
                mock.patch.object(KVM, "load_contract", return_value=contract),
                mock.patch.object(EXEC, "OUTPUT_DIRECTORY_NAME", output_name),
            ]
            for patcher in self.patchers:
                patcher.start()
            self.values = {"root": root, "output": output, "plan_dir": plan_dir, "firmware_vars": firmware_vars}
            return self.values

        def __exit__(self, *_: object) -> None:
            for patcher in getattr(self, "patchers", []): patcher.stop()
            for value in self.values.values():
                if value.name.startswith("m15-03-local-kvm-plan-test-executor-"):
                    shutil.rmtree(value, ignore_errors=True)
            output = self.values.get("output")
            if output is not None:
                shutil.rmtree(output, ignore_errors=True)
            if self.temp is not None: self.temp.cleanup()

    def _reviewed_plan(self) -> "M1503LocalKvmExecutorTest._PlanFixture":
        return self._PlanFixture(self)


if __name__ == "__main__":
    unittest.main()
