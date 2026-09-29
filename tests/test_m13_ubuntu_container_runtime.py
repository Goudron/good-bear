#!/usr/bin/env python3
"""Pure contract tests; no APT, Docker daemon, network, sudo, or VM access."""

from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import provision_m13_ubuntu_container_runtime as RUNTIME


class UbuntuContainerRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.lock = json.loads(
            (ROOT / "config/m13-ubuntu-container-runtime-lock.json").read_text(encoding="utf-8")
        )
        self.packages = RUNTIME.validate_lock(self.lock)

    def test_repository_lock_is_exact_and_fail_closed(self):
        self.assertEqual(self.packages["docker.io"], "29.1.3-0ubuntu3~24.04.2")
        self.assertEqual(self.packages["containerd"], "2.2.1-0ubuntu1~24.04.3")
        self.assertEqual(self.packages["runc"], "1.3.4-0ubuntu1~24.04.1")
        self.assertEqual(self.packages["apparmor"], self.packages["libapparmor1"])
        self.assertEqual(self.lock["runtime"]["invocation"],
                         "sudo -n -- /usr/bin/docker --host unix:///var/run/docker.sock")
        self.assertEqual(self.lock["apt"]["automatic_install_outside_runtime_packages"], "forbidden")

    def test_floating_or_unsigned_snapshot_is_rejected(self):
        for mutation in ("floating", "unsigned", "wrong-host"):
            changed = copy.deepcopy(self.lock)
            if mutation == "floating":
                changed["apt"]["sources"][0] = changed["apt"]["sources"][0].replace(
                    "/20260913T000000Z", "")
            elif mutation == "unsigned":
                changed["apt"]["sources"][0] = changed["apt"]["sources"][0].replace(
                    " [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg]", "")
            else:
                changed["host"]["hostname"] = "some-vm"
            with self.subTest(mutation=mutation), self.assertRaises(RUNTIME.RuntimeError):
                RUNTIME.validate_lock(changed)

    def test_runtime_package_names_and_versions_are_shell_inert(self):
        for field, value in (("name;touch", "1"), ("safe", "1$(id)"), ("UPPER", "1")):
            changed = copy.deepcopy(self.lock)
            changed["apt"]["runtime_packages"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(RUNTIME.RuntimeError, "unsafe"):
                RUNTIME.validate_lock(changed)

    def test_exact_package_arguments_are_sorted_and_versioned(self):
        arguments = RUNTIME.exact_package_arguments({"z": "2", "a": "1:3~u"})
        self.assertEqual(arguments, ["a=1:3~u", "z=2"])
        self.assertTrue(all("=" in item for item in RUNTIME.exact_package_arguments(self.packages)))

    def test_simulation_accepts_only_exact_missing_or_changed_packages(self):
        packages = {"docker.io": "29.1.3-0ubuntu3~24.04.2", "runc": "1.3.4-0ubuntu1~24.04.1"}
        installed = {"runc": packages["runc"]}
        output = "Inst docker.io (29.1.3-0ubuntu3~24.04.2 Ubuntu:24.04/noble-updates [amd64])\n"
        self.assertEqual(RUNTIME.validate_simulation(output, packages, installed),
                         {"docker.io": packages["docker.io"]})

    def test_simulation_rejects_unlocked_wrong_missing_duplicate_and_removal(self):
        packages = {"docker.io": "29.1.3-0ubuntu3~24.04.2"}
        cases = {
            "unlocked": "Inst curl (1.0 Ubuntu [amd64])\nInst docker.io (29.1.3-0ubuntu3~24.04.2 Ubuntu [amd64])\n",
            "wrong": "Inst docker.io (29.1.2 Ubuntu [amd64])\n",
            "missing": "",
            "duplicate": "Inst docker.io (29.1.3-0ubuntu3~24.04.2 Ubuntu [amd64])\n" * 2,
            "removal": "Remv old-package [1.0]\nInst docker.io (29.1.3-0ubuntu3~24.04.2 Ubuntu [amd64])\n",
        }
        for name, output in cases.items():
            with self.subTest(name=name), self.assertRaises(RUNTIME.RuntimeError):
                RUNTIME.validate_simulation(output, packages, {})

    def test_sudo_requires_an_absolute_program_and_fixed_noninteractive_prefix(self):
        with self.assertRaisesRegex(RUNTIME.RuntimeError, "absolute"):
            RUNTIME.sudo(["docker", "info"])
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(RUNTIME, "execute", return_value=completed) as execute:
            RUNTIME.sudo(["/usr/bin/true"], timeout=7)
        self.assertEqual(execute.call_args.args[0], ["/usr/bin/sudo", "-n", "--", "/usr/bin/true"])
        self.assertEqual(execute.call_args.kwargs["timeout"], 7)

    def test_live_runtime_verification_binds_packages_daemon_and_security(self):
        version = {"Server": {"Version": "29.1.3", "Os": "linux", "Arch": "amd64"}}
        info = {"OSType": "linux", "Architecture": "x86_64", "CgroupVersion": "2", "Driver": "overlayfs",
                "SecurityOptions": ["name=apparmor,profile=default", "name=seccomp,profile=builtin", "name=cgroupns"]}
        command = SimpleNamespace(stdout="LISTEN 0 4096 127.0.0.1:22 0.0.0.0:* users:sshd\n")
        socket_stat = SimpleNamespace(st_mode=stat.S_IFSOCK)
        with mock.patch.object(RUNTIME, "verify_host", return_value={"hostname": "ubuntu-server"}), \
                mock.patch.object(RUNTIME, "installed_packages", return_value=self.packages), \
                mock.patch.object(Path, "is_file", return_value=True), \
                mock.patch.object(Path, "is_symlink", return_value=False), \
                mock.patch.object(Path, "exists", return_value=True), \
                mock.patch.object(Path, "stat", return_value=socket_stat), \
                mock.patch.object(RUNTIME.os, "access", return_value=True), \
                mock.patch.object(RUNTIME, "docker_json", side_effect=[version, info]), \
                mock.patch.object(RUNTIME, "sudo", return_value=command):
            evidence = RUNTIME.verify_runtime(self.lock)
        self.assertTrue(evidence["runtime_verified"])
        self.assertFalse(evidence["docker"]["tcp_listener"])
        self.assertEqual(evidence["docker"]["server_version"], "29.1.3")

    def test_live_runtime_rejects_changed_engine_missing_security_and_tcp_listener(self):
        base_version = {"Server": {"Version": "29.1.3", "Os": "linux", "Arch": "amd64"}}
        base_info = {"OSType": "linux", "Architecture": "x86_64", "CgroupVersion": "2", "Driver": "overlayfs",
                     "SecurityOptions": ["name=apparmor,profile=default", "name=seccomp,profile=builtin"]}
        cases = []
        changed_version = copy.deepcopy(base_version)
        changed_version["Server"]["Version"] = "29.1.4"
        cases.append((changed_version, base_info, ""))
        changed_info = copy.deepcopy(base_info)
        changed_info["SecurityOptions"] = ["name=seccomp,profile=builtin"]
        cases.append((base_version, changed_info, ""))
        cases.append((base_version, base_info, "LISTEN users:((\"dockerd\",pid=5,fd=3))\n"))
        socket_stat = SimpleNamespace(st_mode=stat.S_IFSOCK)
        for version, info, listeners in cases:
            with self.subTest(version=version, info=info, listeners=listeners), \
                    mock.patch.object(RUNTIME, "verify_host", return_value={}), \
                    mock.patch.object(RUNTIME, "installed_packages", return_value=self.packages), \
                    mock.patch.object(Path, "is_file", return_value=True), \
                    mock.patch.object(Path, "is_symlink", return_value=False), \
                    mock.patch.object(Path, "exists", return_value=True), \
                    mock.patch.object(Path, "stat", return_value=socket_stat), \
                    mock.patch.object(RUNTIME.os, "access", return_value=True), \
                    mock.patch.object(RUNTIME, "docker_json", side_effect=[version, info]), \
                    mock.patch.object(RUNTIME, "sudo", return_value=SimpleNamespace(stdout=listeners)):
                with self.assertRaises(RUNTIME.RuntimeError):
                    RUNTIME.verify_runtime(self.lock)

    def test_report_must_be_new_and_outside_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary).resolve() / "runtime.json"
            RUNTIME.write_report(target, {"runtime_verified": True})
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            with self.assertRaises(RUNTIME.RuntimeError):
                RUNTIME.write_report(target, {})
        with self.assertRaisesRegex(RUNTIME.RuntimeError, "outside"):
            RUNTIME.write_report(ROOT / "build/runtime.json", {})

    def test_cli_failure_is_sanitized_and_writes_no_success_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary).resolve() / "runtime.json"
            argv = ["runtime", "verify", "--report", str(report)]
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(RUNTIME, "verify_runtime", side_effect=ValueError("secret response")), \
                    redirect_stdout(io.StringIO()) as output:
                self.assertEqual(RUNTIME.main(), 1)
            self.assertNotIn("secret response", output.getvalue())
            self.assertFalse(report.exists())


if __name__ == "__main__":
    unittest.main()
