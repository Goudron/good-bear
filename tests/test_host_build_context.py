#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import hashlib
import json
from unittest import mock
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "host_build_context", ROOT / "tools" / "host_build_context.py"
)
assert SPEC and SPEC.loader
CONTEXT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CONTEXT
SPEC.loader.exec_module(CONTEXT)


class HostBuildContextTest(unittest.TestCase):
    def test_source_is_derived_from_the_pinned_firefox_156_baseline(self) -> None:
        baseline = json.loads(
            (ROOT / "config" / "firefox-baseline.json").read_text(encoding="utf-8")
        )
        self.assertEqual(baseline["version"], "156.0")
        self.assertEqual(CONTEXT.FIREFOX_WORKTREE_NAME, "firefox-156.0")
        self.assertEqual(
            CONTEXT.SOURCE,
            ROOT / "source" / "worktrees" / "firefox-156.0",
        )
        self.assertNotIn("firefox-154.0", str(CONTEXT.SOURCE))
        self.assertNotIn("firefox-155.0.1", str(CONTEXT.SOURCE))

    def toolchain_fixture(self, temporary: Path) -> tuple[Path, Path]:
        toolchain = temporary / "toolchain"
        lock = temporary / "toolchain-lock.json"
        temporary.mkdir(parents=True, exist_ok=True)
        lock_data = {
            "target": "x86_64-unknown-linux-gnu",
            "components": [{
                "id": "llvm", "version": "22.1.8",
                "archive": {"sha256": "a" * 64},
            }],
        }
        lock.write_text(json.dumps(lock_data), encoding="utf-8")
        marker = {
            "lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
            "target": lock_data["target"],
            "components": [{
                "id": "llvm", "version": "22.1.8", "archive_sha256": "a" * 64,
            }],
        }
        (toolchain / ".good-bear-toolchain.json").parent.mkdir(parents=True)
        (toolchain / ".good-bear-toolchain.json").write_text(json.dumps(marker), encoding="utf-8")
        for _, (_, relative) in CONTEXT.TOOLCHAIN_EXECUTABLES.items():
            executable = toolchain / relative
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
        inspector = toolchain / "llvm/bin/llvm-objdump"
        inspector.write_text("#!/bin/sh\n", encoding="utf-8")
        inspector.chmod(0o755)
        linker = toolchain / "llvm/bin/lld"
        linker.write_text("#!/bin/sh\n", encoding="utf-8")
        linker.chmod(0o755)
        return toolchain, lock

    def test_rejects_object_directory_outside_project_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTEXT.ContextError, "artifacts"):
                CONTEXT.HostBuildContext.create(Path(temporary))

    def test_russian_repack_context_is_explicit_about_the_two_locale_roles(self) -> None:
        context = CONTEXT.HostBuildContext.create(
            ROOT / "artifacts" / "development" / "context-test-obj"
        )
        rendered = context.render("russian-repack")
        self.assertIn("base input locale: en-US (internal only)", rendered)
        self.assertIn("claimed artifact locale: ru", rendered)
        self.assertIn("sole shipped locale: ru", rendered)

    def test_engine_test_cannot_claim_a_localized_artifact(self) -> None:
        context = CONTEXT.HostBuildContext.create(
            ROOT / "artifacts" / "development" / "context-test-obj"
        )
        rendered = context.render("engine-test")
        self.assertIn("not Russian UI evidence", rendered)
        self.assertIn("claimed artifact locale: en-US input only", rendered)

    def test_supplier_wrapper_uses_canonical_base_and_reports_actual_inputs(self) -> None:
        from test_build_host_russian import bound_context, DUMMY_KEY

        for release in (False, True):
            with bound_context(release_lto=release) as (context, key, _, _):
                self.assertEqual(context.base_mozconfig.name,
                                 "mozconfig.release-lto" if release else "mozconfig.host")
                self.assertEqual(context.mozconfig.parent, context.private_input_dir)
                context.validate_safebrowsing()
                before = context.mozconfig.stat().st_mtime_ns
                reused = context.with_safebrowsing_key(key)
                self.assertEqual(reused.mozconfig, context.mozconfig)
                self.assertEqual(reused.mozconfig.stat().st_mtime_ns, before)
                self.assertEqual(context.objdir.stat().st_mode & 0o777, 0o700)
                toolchain, lock = self.toolchain_fixture(context.objdir / "fixture-tools")
                with mock.patch.dict(context.environment.__func__.__globals__,
                                     {"TOOLCHAIN": toolchain, "TOOLCHAIN_LOCK": lock}):
                    environment = context.environment()
                self.assertEqual(environment["MOZCONFIG"], str(context.mozconfig))
                self.assertNotEqual(environment["MOZCONFIG"], str(context.base_mozconfig))
                rendered = context.render("russian-repack")
                self.assertIn("MOZCONFIG: " + str(context.mozconfig), rendered)
                for name, digest in context.safebrowsing_evidence().items():
                    self.assertIn(name + ": " + digest, rendered)
                self.assertNotIn(DUMMY_KEY.decode(), rendered)

    def test_key_bearing_objdir_cannot_be_reopened_to_other_users(self) -> None:
        from test_build_host_russian import bound_context

        with bound_context() as (context, _, _, _):
            context.objdir.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "owner-only"):
                context.validate_safebrowsing()

    def test_supplier_contract_mutation_fails_before_reusing_environment(self) -> None:
        from test_build_host_russian import bound_context

        with bound_context() as (context, _, contract, _):
            data = json.loads(contract.read_text())
            data["allowed_api_services"].append("other.googleapis.com")
            contract.write_text(json.dumps(data))
            with self.assertRaisesRegex(RuntimeError, "supplier contract"):
                context.validate_safebrowsing()
            with self.assertRaisesRegex(RuntimeError, "supplier contract"):
                context.environment()

    def test_keyless_engine_context_cannot_be_used_as_russian_key_binding(self) -> None:
        context = CONTEXT.HostBuildContext.create(ROOT / "artifacts" / "development" / "engine-only-test")
        self.assertEqual(context.mozconfig, CONTEXT.MOZCONFIG)
        with self.assertRaisesRegex(CONTEXT.ContextError, "explicit verified"):
            context.validate_safebrowsing()

    def test_context_environment_uses_the_single_host_mozconfig(self) -> None:
        context = CONTEXT.HostBuildContext.create(
            ROOT / "artifacts" / "development" / "context-test-obj"
        )
        environment = context.environment()
        self.assertEqual(environment["MOZCONFIG"], str(CONTEXT.MOZCONFIG))
        self.assertEqual(environment["MOZ_OBJDIR"], str(context.objdir))
        temporary_root = CONTEXT.ROOT / "artifacts" / "build-tmp"
        self.assertEqual(environment["TMPDIR"], str(temporary_root.resolve()))
        self.assertEqual(environment["TMP"], environment["TMPDIR"])
        self.assertEqual(environment["TEMP"], environment["TMPDIR"])
        self.assertTrue(temporary_root.is_dir())

    def test_release_lto_requires_the_dedicated_reviewed_mozconfig(self) -> None:
        context = CONTEXT.HostBuildContext.create(
            ROOT / "artifacts" / "development" / "context-test-release-lto-obj",
            release_lto=True,
        )
        self.assertEqual(context.mozconfig, CONTEXT.RELEASE_LTO_MOZCONFIG)
        self.assertEqual(context.environment()["MOZCONFIG"], str(CONTEXT.RELEASE_LTO_MOZCONFIG))
        self.assertIn("link-time optimization: full", context.render("russian-repack"))

    def test_environment_prepends_locked_llvm_and_binds_owned_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            toolchain, lock = self.toolchain_fixture(Path(temporary))
            context = CONTEXT.HostBuildContext.create(
                ROOT / "artifacts" / "development" / "context-test-obj"
            )
            with mock.patch.object(CONTEXT, "TOOLCHAIN", toolchain), mock.patch.object(
                CONTEXT, "TOOLCHAIN_LOCK", lock
            ), mock.patch.dict(CONTEXT.os.environ, {"PATH": "/system/bin"}, clear=True):
                environment = context.environment()
            self.assertEqual(environment["PATH"], f"{toolchain / 'llvm/bin'}:/system/bin")
            for variable, (_, relative) in CONTEXT.TOOLCHAIN_EXECUTABLES.items():
                self.assertEqual(environment[variable], str((toolchain / relative).resolve()))
            self.assertEqual(environment["LD"], str((toolchain / "llvm/bin/lld").resolve()))
            self.assertEqual(environment["LDFLAGS"], "-fuse-ld=lld")

    def test_environment_discards_inherited_compiler_and_linker_settings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            toolchain, lock = self.toolchain_fixture(Path(temporary))
            context = CONTEXT.HostBuildContext.create(
                ROOT / "artifacts" / "development" / "context-test-obj"
            )
            inherited = {
                "PATH": "/system/bin",
                "CC": "/usr/bin/gcc",
                "CXX": "/usr/bin/g++",
                "LD": "/usr/bin/ld",
                "CXXFLAGS": "-fno-rtti",
                "LDFLAGS": "-fuse-ld=gold",
                "MOZ_CONFIGURE_OPTIONS": "untrusted-options",
                "MOZ_GOOGLE_SAFEBROWSING_API_KEY": "untrusted-inherited-value",
                "GOODBEAR_SAFEBROWSING_KEY_FILE": "untrusted-keyfile",
            }
            with mock.patch.object(CONTEXT, "TOOLCHAIN", toolchain), mock.patch.object(
                CONTEXT, "TOOLCHAIN_LOCK", lock
            ), mock.patch.dict(CONTEXT.os.environ, inherited, clear=True):
                environment = context.environment()
            self.assertEqual(environment["CC"], str((toolchain / "llvm/bin/clang").resolve()))
            self.assertEqual(environment["CXX"], str((toolchain / "llvm/bin/clang++").resolve()))
            self.assertEqual(environment["LD"], str((toolchain / "llvm/bin/lld").resolve()))
            self.assertNotIn("CXXFLAGS", environment)
            self.assertEqual(environment["LDFLAGS"], "-fuse-ld=lld")
            self.assertNotIn("MOZ_CONFIGURE_OPTIONS", environment)
            self.assertNotIn("MOZ_GOOGLE_SAFEBROWSING_API_KEY", environment)
            self.assertNotIn("GOODBEAR_SAFEBROWSING_KEY_FILE", environment)

    def test_environment_preserves_clangxx_driver_name_after_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            toolchain, lock = self.toolchain_fixture(Path(temporary))
            clangxx = toolchain / "llvm/bin/clang++"
            clangxx.unlink()
            target = toolchain / "llvm/bin/clang-22"
            target.write_text("#!/bin/sh\n", encoding="utf-8")
            target.chmod(0o755)
            clangxx.symlink_to("clang-22")
            context = CONTEXT.HostBuildContext.create(
                ROOT / "artifacts" / "development" / "context-test-obj"
            )
            with mock.patch.object(CONTEXT, "TOOLCHAIN", toolchain), mock.patch.object(
                CONTEXT, "TOOLCHAIN_LOCK", lock
            ):
                environment = context.environment()
            self.assertEqual(environment["CXX"], str(clangxx))
            self.assertNotEqual(environment["CXX"], str(clangxx.resolve()))

    def test_rejects_nonempty_inherited_compiler_or_linker_settings(self) -> None:
        with self.assertRaisesRegex(CONTEXT.ContextError, "CXX, LDFLAGS"):
            CONTEXT.reject_conflicting_toolchain_environment({
                "CXX": "/usr/bin/g++",
                "LDFLAGS": "-fuse-ld=gold",
            })

    def test_validation_fails_closed_for_missing_toolchain_marker_or_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            toolchain, lock = self.toolchain_fixture(Path(temporary))
            with mock.patch.object(CONTEXT, "TOOLCHAIN", toolchain), mock.patch.object(
                CONTEXT, "TOOLCHAIN_LOCK", lock
            ):
                (toolchain / ".good-bear-toolchain.json").unlink()
                with self.assertRaisesRegex(CONTEXT.ContextError, "toolchain marker"):
                    CONTEXT._verified_toolchain_executables()
                toolchain, lock = self.toolchain_fixture(Path(temporary) / "second")
                with mock.patch.object(CONTEXT, "TOOLCHAIN", toolchain), mock.patch.object(
                    CONTEXT, "TOOLCHAIN_LOCK", lock
                ):
                    (toolchain / "llvm/bin/llvm-objdump").unlink()
                    with self.assertRaisesRegex(CONTEXT.ContextError, "LLVM object inspector"):
                        CONTEXT._verified_toolchain_executables()


if __name__ == "__main__":
    unittest.main()
