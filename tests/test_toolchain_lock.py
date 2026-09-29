#!/usr/bin/env python3

from __future__ import annotations

import io
import importlib.util
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "install_toolchain.py"
SPEC = importlib.util.spec_from_file_location("install_toolchain", MODULE_PATH)
assert SPEC and SPEC.loader
TOOLCHAIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLCHAIN)


class ToolchainLockTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads((ROOT / "config" / "toolchain-lock.json").read_text(encoding="utf-8"))

    def test_repository_lock_is_consistent(self) -> None:
        TOOLCHAIN.validate_lock(self.lock)

    def test_rejects_non_russian_toolchain_lock(self) -> None:
        self.lock["release_locale"] = "en-US"
        with self.assertRaisesRegex(TOOLCHAIN.ToolchainError, "Russian-only"):
            TOOLCHAIN.validate_lock(self.lock)

    def test_rejects_a_floating_or_unhashed_archive(self) -> None:
        self.lock["components"][0]["archive"]["sha256"] = "not-a-hash"
        with self.assertRaisesRegex(TOOLCHAIN.ToolchainError, "sha256"):
            TOOLCHAIN.validate_lock(self.lock)

    def test_rejects_wrong_node_or_npm_version(self) -> None:
        node = next(component for component in self.lock["components"]
                    if component["id"] == "node-and-npm")
        node["npm_version"] = "11.17.1"
        with self.assertRaisesRegex(TOOLCHAIN.ToolchainError, "npm pin"):
            TOOLCHAIN.validate_lock(self.lock)

    def test_rejects_an_llvm_target_exception(self) -> None:
        self.lock["components"][1]["exception"] = {
            "reason": "test",
            "evidence": "test",
            "owner": "test",
            "review_on_or_before": "2026-09-22",
        }
        with self.assertRaisesRegex(TOOLCHAIN.ToolchainError, "admits no uninstalled"):
            TOOLCHAIN.validate_lock(self.lock)

    def test_rejects_wasi_sysroot_pin_drift(self) -> None:
        self.lock["components"][2]["archive"]["sha256"] = "not-a-hash"
        with self.assertRaisesRegex(TOOLCHAIN.ToolchainError, "sha256"):
            TOOLCHAIN.validate_lock(self.lock)

    def test_host_native_verification_exercises_llvm_and_defers_docker_gate(self) -> None:
        prefix = Path("/verified/toolchain")
        with (mock.patch.object(TOOLCHAIN, "check_prefix_versions") as versions,
              mock.patch.object(TOOLCHAIN, "focused_compatibility") as compatibility,
              mock.patch.object(TOOLCHAIN, "target_compatibility") as target):
            TOOLCHAIN.verify_installed_toolchain(
                prefix, self.lock, host_native=True, target_image="pinned-image"
            )
        versions.assert_called_once_with(self.lock, prefix, include_llvm=True)
        compatibility.assert_called_once_with(prefix, include_llvm=True)
        target.assert_not_called()

    def test_default_verification_preserves_docker_target_gate(self) -> None:
        prefix = Path("/verified/toolchain")
        with (mock.patch.object(TOOLCHAIN, "check_prefix_versions") as versions,
              mock.patch.object(TOOLCHAIN, "focused_compatibility") as compatibility,
              mock.patch.object(TOOLCHAIN, "target_compatibility") as target):
            TOOLCHAIN.verify_installed_toolchain(
                prefix, self.lock, host_native=False, target_image="pinned-image"
            )
        versions.assert_called_once_with(self.lock, prefix, include_llvm=False)
        compatibility.assert_called_once_with(prefix, include_llvm=False)
        target.assert_called_once_with(prefix, "pinned-image")

    def test_cbindgen_build_puts_staged_rust_before_host_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            rust_bin = stage / "rust" / "bin"
            rust_bin.mkdir(parents=True)
            for command in ("cargo", "rustc"):
                (rust_bin / command).touch()
            extracted = stage / "extracted-cbindgen"
            extracted.mkdir()
            built_binary = extracted / "target" / "release" / "cbindgen"

            def fake_run(command, *, cwd=None, env=None):
                self.assertEqual(command, [str(rust_bin / "cargo"), "build", "--release", "--locked"])
                self.assertEqual(cwd, extracted)
                self.assertEqual(env["PATH"].split(os.pathsep)[0], str(rust_bin))
                self.assertIn("/host/bin", env["PATH"].split(os.pathsep)[1:])
                self.assertEqual(env["CARGO_HOME"], str(stage / "cargo-home"))
                self.assertEqual(env["RUSTUP_HOME"], str(stage / "rustup-home"))
                built_binary.parent.mkdir(parents=True)
                built_binary.touch()
                return ""

            with (mock.patch.object(TOOLCHAIN, "safe_extract", return_value=extracted),
                  mock.patch.object(TOOLCHAIN, "run", side_effect=fake_run),
                  mock.patch.dict(os.environ, {"PATH": "/host/bin"}, clear=True)):
                TOOLCHAIN.install_cbindgen(Path("cbindgen.tar.gz"), stage)

            self.assertTrue((stage / "cbindgen" / "bin" / "cbindgen").is_file())

    def test_absolute_npm_wrapper_resolves_staged_node_from_prefix_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            node_bin = prefix / "node" / "bin"
            node_bin.mkdir(parents=True)
            node = node_bin / "node"
            node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            node.chmod(0o755)
            npm = node_bin / "npm"
            npm.write_text("#!/usr/bin/env node\n", encoding="utf-8")
            npm.chmod(0o755)

            with mock.patch.dict(os.environ, {"PATH": "/host/bin"}, clear=True):
                env = TOOLCHAIN.toolchain_environment(prefix)
                self.assertEqual(
                    env["PATH"].split(os.pathsep)[:3],
                    [str(prefix / "rust" / "bin"), str(node_bin), "/host/bin"],
                )
                self.assertEqual(TOOLCHAIN.run([str(npm), "--version"], env=env), "")

    def test_wasi_focused_checks_use_wasi_sdk_compilers_not_llvm(self) -> None:
        prefix = Path("/verified/toolchain")
        with mock.patch.object(TOOLCHAIN, "run", return_value="") as run:
            TOOLCHAIN.focused_compatibility(prefix, include_llvm=True)
        wasi_commands = [call.args[0] for call in run.call_args_list
                         if "--target=wasm32-wasi" in call.args[0]]
        self.assertEqual(
            [command[0] for command in wasi_commands],
            [str(prefix / "wasi-sdk" / "bin" / "clang"),
             str(prefix / "wasi-sdk" / "bin" / "clang++")],
        )
        self.assertNotIn(str(prefix / "llvm" / "bin" / "clang"),
                         [command[0] for command in wasi_commands])

    def test_wasi_clock_smoke_links_the_locked_emulation_library(self) -> None:
        prefix = Path("/verified/toolchain")
        with mock.patch.object(TOOLCHAIN, "run", return_value="") as run:
            TOOLCHAIN.focused_compatibility(prefix, include_llvm=True)
        clock_command = next(
            call.args[0] for call in run.call_args_list
            if "check-wasi.c" in " ".join(call.args[0])
        )
        self.assertIn("-D_WASI_EMULATED_PROCESS_CLOCKS", clock_command)
        self.assertIn("-lwasi-emulated-process-clocks", clock_command)

    def test_host_native_wasi_check_uses_the_locked_sdk_sysroot(self) -> None:
        self.assertEqual(
            TOOLCHAIN.wasi_sysroot(Path("/verified/toolchain")),
            Path("/verified/toolchain/wasi-sdk/share/wasi-sysroot"),
        )

    def test_safe_extract_rejects_lexical_archive_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            archive = temporary_path / "unsafe.tar"
            with tarfile.open(archive, "w") as output:
                member = tarfile.TarInfo("toolchain/../../escape")
                member.size = 1
                output.addfile(member, io.BytesIO(b"x"))

            with self.assertRaisesRegex(TOOLCHAIN.ToolchainError, "path escapes destination"):
                TOOLCHAIN.safe_extract(archive, temporary_path / "extract")

    def test_safe_extract_does_not_resolve_each_archive_member_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            archive = temporary_path / "safe.tar"
            with tarfile.open(archive, "w") as output:
                member = tarfile.TarInfo("toolchain/bin/tool")
                member.size = 1
                output.addfile(member, io.BytesIO(b"x"))

            with mock.patch.object(TOOLCHAIN.Path, "resolve", side_effect=AssertionError):
                root = TOOLCHAIN.safe_extract(archive, temporary_path / "extract")

            self.assertEqual(root, temporary_path / "extract" / "toolchain")
            self.assertEqual((root / "bin" / "tool").read_bytes(), b"x")


if __name__ == "__main__":
    unittest.main()
