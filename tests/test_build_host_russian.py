#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from contextlib import contextmanager, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "build_host_russian", ROOT / "tools" / "build_host_russian.py"
)
assert SPEC and SPEC.loader
BUILD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BUILD
SPEC.loader.exec_module(BUILD)

DUMMY_KEY = b"AIza" + b"0" * 35


@contextmanager
def bound_context(*, release_lto=False):
    """Real private-file validation with synthetic inputs; no native build claim."""
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary).resolve()
        root = directory / "project"
        source = root / "source"
        source.mkdir(parents=True)
        (source / ".good-bear-materialization.json").write_text('{"fixture":true}\n')
        base = root / "mozconfig.host"
        base.write_text("# canonical fixture\n")
        release_base = root / "mozconfig.release-lto"
        release_base.write_text("# canonical release fixture\nexport MOZ_LTO=full\n")
        key = directory / "supplier.key"
        key.write_bytes(DUMMY_KEY + b"\n")
        key.chmod(0o600)
        contract = root / "supplier.json"
        contract.write_text(json.dumps({
            "schema_version": 1, "task": "GB100-M15-12", "supplier": "Google Safe Browsing",
            "allowed_api_services": ["safebrowsing.googleapis.com"],
            "key_value_in_source": False, "key_value_in_build_logs": False,
            "key_file_sha256": hashlib.sha256(key.read_bytes()).hexdigest(),
        }))
        values = {"ROOT": root, "SOURCE": source, "ARTIFACTS": root / "artifacts",
                  "MOZCONFIG": base, "RELEASE_LTO_MOZCONFIG": release_base,
                  "SAFEBROWSING_CONTRACT": contract}
        # This class may have been imported before another unittest module
        # loaded a separate host_build_context instance. Patch its actual globals.
        host_globals = BUILD.HostBuildContext.create.__func__.__globals__
        with mock.patch.dict(host_globals, values), mock.patch.object(BUILD, "SOURCE", source):
            context = BUILD.HostBuildContext.create(root / "artifacts" / "obj", release_lto=release_lto)
            context = context.with_safebrowsing_key(key)
            yield context, key, contract, source


def config_fixture(context, source, *, key=DUMMY_KEY.decode()):
    path = context.objdir / "config.status"
    path.write_text("\n".join((
        "from mozbuild.configure.constants import *",
        "defines = {}",
        "substs = " + repr({"MOZ_GOOGLE_SAFEBROWSING_API_KEY": key}),
        "mozconfig = " + repr(str(context.mozconfig)),
        "topobjdir = " + repr(str(context.objdir)),
        "topsrcdir = " + repr(str(source)),
        "__all__ = ['topobjdir', 'topsrcdir', 'defines', 'substs', 'mozconfig']",
        "if __name__ == '__main__':\n"
        "    from mozbuild.config_status import config_status\n"
        "    args = dict([(name, globals()[name]) for name in __all__])\n"
        "    config_status(**args)",
    )) + "\n")
    return path


class HostRussianBuildTest(unittest.TestCase):
    def test_repack_is_russian_only_and_follows_base_package(self) -> None:
        self.assertEqual(
            BUILD.command_plan(1),
            (
                ("build base Firefox inputs", ("build", "-j1")),
                ("package internal base inputs", ("package",)),
                ("repack the only shipped locale: ru", ("build", "installers-ru")),
            ),
        )

    def test_explicit_configuration_is_available_without_being_default(self) -> None:
        self.assertEqual(
            BUILD.command_plan(4, configure=True)[0],
            ("configure base Firefox inputs", ("configure",)),
        )

    def test_only_an_unconfigured_object_directory_needs_explicit_configure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            objdir = Path(temporary)
            self.assertTrue(BUILD.requires_initial_configure(objdir))
            (objdir / "config.status").touch()
            self.assertFalse(BUILD.requires_initial_configure(objdir))

    def test_rejects_more_than_four_build_jobs(self) -> None:
        with self.assertRaisesRegex(BUILD.BuildError, "between 1 and 4"):
            BUILD.command_plan(5)

    def test_build_uses_the_shared_canonical_host_context(self) -> None:
        source = (ROOT / "tools" / "build_host_russian.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "HostBuildContext.create(args.objdir, release_lto=args.release_lto)",
            source,
        )
        self.assertIn('context.render("russian-repack")', source)
        self.assertIn("GOODBEAR_RUSSIAN_PKI_BUILD_INPUT_DIR", source)
        self.assertIn("verify_russian_pki_build_inputs", source)
        self.assertIn("M3-04 Russian PKI build-input verification", source)
        self.assertIn("reject_conflicting_toolchain_environment", source)
        self.assertIn("wasm2c_host_cpp_probe", source)
        self.assertIn("--release-lto", source)

    def test_release_locale_boundary_is_enabled_only_for_russian_repack(self) -> None:
        environment = {"BASE": "value"}
        self.assertEqual(
            BUILD.russian_repack_environment(environment),
            {"BASE": "value", "GOODBEAR_RUSSIAN_ONLY": "1"},
        )
        self.assertNotIn("GOODBEAR_RUSSIAN_ONLY", environment)

    def test_mach_receives_the_complete_context_environment(self) -> None:
        captured: dict[str, object] = {}

        class Process:
            stdout = io.BytesIO(b"")

            def wait(self) -> int:
                return 0

        def popen(*args: object, **kwargs: object) -> Process:
            captured["args"] = args
            captured["kwargs"] = kwargs
            return Process()

        environment = {
            "PATH": "/locked/llvm/bin:/system/bin",
            "CC": "/locked/llvm/bin/clang",
            "CXX": "/locked/llvm/bin/clang++",
            "RUSTC": "/locked/rust/bin/rustc",
            "CARGO": "/locked/rust/bin/cargo",
            "NODEJS": "/locked/node/bin/node",
            "CBINDGEN": "/locked/cbindgen/bin/cbindgen",
        }
        with bound_context() as (context, _, _, _):
            environment.update(MOZCONFIG=str(context.mozconfig), MOZ_OBJDIR=str(context.objdir))
            with mock.patch.object(BUILD.subprocess, "Popen", side_effect=popen):
                BUILD.run(("build", "-j1"), environment, context=context)
        self.assertEqual(captured["args"][0], [sys.executable, "mach", "build", "-j1"])
        self.assertIs(captured["kwargs"]["env"], environment)

    def test_stages_and_uses_exactly_one_internal_base_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary) / "dist"
            dist.mkdir()
            package = dist / "goodbear-1.0.en-US.linux-x86_64.tar.xz"
            package.touch()
            xpi = dist / "linux-x86_64" / "xpi"
            xpi.mkdir(parents=True)
            auxiliary = xpi / "goodbear-1.0.en-US.langpack.xpi"
            auxiliary.touch()
            staged = BUILD.stage_base_inputs(Path(temporary))
            self.assertEqual(staged.name, package.name)
            self.assertFalse(package.exists())
            self.assertTrue(
                (
                    Path(temporary)
                    / BUILD.BASE_INPUT_DIR
                    / "linux-x86_64/xpi"
                    / auxiliary.name
                ).is_file()
            )
            (Path(temporary) / BUILD.BASE_INPUT_DIR / "goodbear-2.0.en-US.linux-x86_64.tar.xz").touch()
            with self.assertRaisesRegex(BUILD.BuildError, "exactly one"):
                BUILD.find_base_package(Path(temporary))

    def test_cli_rejects_missing_explicit_key_before_a_build(self):
        with mock.patch.object(sys, "argv", ["build_host_russian.py", "--objdir", "artifacts/test"]), \
                mock.patch.object(BUILD.subprocess, "Popen") as process, \
                mock.patch.object(sys, "stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                BUILD.main()
        self.assertEqual(caught.exception.code, 2)
        process.assert_not_called()

    def test_real_child_output_redacts_split_key_before_stdout(self):
        with bound_context() as (context, key, _, source):
            # An actual tiny child process, not a compiler or a mocked gate.
            (source / "mach").write_text(
                "import os, pathlib, shlex, sys\n"
                "line=pathlib.Path(os.environ['MOZCONFIG']).read_text().splitlines()[-1]\n"
                "path=shlex.split(line)[1].split('=',1)[1]\n"
                "value=pathlib.Path(path).read_bytes().strip()\n"
                "sys.stdout.buffer.write('начало '.encode()); sys.stdout.buffer.flush()\n"
                "for byte in value: sys.stdout.buffer.write(bytes([byte])); sys.stdout.buffer.flush()\n"
                "sys.stdout.buffer.write(b' end\\n'); sys.stdout.buffer.flush()\n")
            environment = {"MOZCONFIG": str(context.mozconfig), "MOZ_OBJDIR": str(context.objdir)}
            output = io.StringIO()
            with redirect_stdout(output):
                BUILD.run(("configure",), environment, context=context)
            self.assertIn("начало [REDACTED-SAFEBROWSING-KEY] end", output.getvalue())
            self.assertNotIn(DUMMY_KEY.decode(), output.getvalue())
            key.write_bytes(b"AIza" + b"1" * 35 + b"\n")
            with mock.patch.object(BUILD.subprocess, "Popen") as process:
                with self.assertRaises(BUILD.BuildInputError):
                    BUILD.run(("package",), environment, context=context)
                process.assert_not_called()

    def test_wrong_effective_environment_never_starts_mach(self):
        with bound_context() as (context, _, _, _):
            with mock.patch.object(BUILD.subprocess, "Popen") as process:
                with self.assertRaisesRegex(BUILD.BuildError, "environment differs"):
                    BUILD.run(("build",), {"MOZCONFIG": "unverified"}, context=context)
                process.assert_not_called()

    def test_config_status_literal_parser_never_executes_and_rejects_wrong_key(self):
        with bound_context() as (context, _, _, source):
            path = config_fixture(context, source)
            sentinel = context.objdir / "EXECUTED"
            self.assertEqual(BUILD.verify_configured_key(context), hashlib.sha256(path.read_bytes()).hexdigest())
            with path.open("a") as stream:
                stream.write("raise RuntimeError('must never execute')\n")
                stream.write("open(" + repr(str(sentinel)) + ", 'w').close()\n")
            with self.assertRaisesRegex(BUILD.BuildError, "unsupported config.status statement"):
                BUILD.verify_configured_key(context)
            self.assertFalse(sentinel.exists())
            for value in (None, "", "no-google-safebrowsing-api-key", "AIza" + "1" * 35):
                config_fixture(context, source, key=value)
                with self.assertRaisesRegex(BUILD.BuildError, "configure and rebuild"):
                    BUILD.verify_configured_key(context)
            for text in ("substs = dangerous()\n", "this is invalid python !!!\n",
                         "substs = {}\nsubsts = {}\n"):
                path.write_text(text)
                with self.assertRaises(BUILD.BuildError):
                    BUILD.verify_configured_key(context)

    def test_config_status_requires_exact_source_objdir_and_wrapper(self):
        with bound_context() as (context, _, _, source):
            for name in ("mozconfig", "topobjdir", "topsrcdir"):
                path = config_fixture(context, source)
                with path.open("a") as stream:
                    stream.write(name + " = 'other'\n")
                with self.assertRaises(BUILD.BuildError):
                    BUILD.verify_configured_key(context)

    def test_repack_requires_successful_package_receipt_and_unchanged_bytes(self):
        with bound_context() as (context, _, _, source):
            path = config_fixture(context, source)
            folder = context.objdir / BUILD.BASE_INPUT_DIR
            folder.mkdir()
            package = folder / "goodbear-fixture.en-US.linux-x86_64.tar.xz"
            package.write_bytes(b"synthetic packaged bytes; not a browser")
            with self.assertRaisesRegex(BUILD.BuildError, "lacks verified base evidence"):
                BUILD.verify_repack_base(context)
            BUILD.record_base_package(context, package)
            self.assertEqual(BUILD.verify_repack_base(context), package)
            original = package.read_bytes()
            package.write_bytes(b"changed package")
            with self.assertRaisesRegex(BUILD.BuildError, "inputs changed"):
                BUILD.verify_repack_base(context)
            package.write_bytes(original)
            with path.open("a") as stream:
                stream.write("# changed configuration\n")
            with self.assertRaisesRegex(BUILD.BuildError, "inputs changed"):
                BUILD.verify_repack_base(context)

    def test_receipt_cannot_be_recorded_for_keyless_base(self):
        with bound_context() as (context, _, _, source):
            config_fixture(context, source, key="no-google-safebrowsing-api-key")
            package = context.objdir / "base.tar.xz"
            package.write_bytes(b"fixture")
            with self.assertRaisesRegex(BUILD.BuildError, "configure and rebuild"):
                BUILD.record_base_package(context, package)
            self.assertFalse((context.private_input_dir / "base-package-binding.json").exists())

    def test_repack_rejects_external_symlink_package(self):
        with bound_context() as (context, _, _, source):
            config_fixture(context, source)
            folder = context.objdir / BUILD.BASE_INPUT_DIR
            folder.mkdir()
            external = source / "external-package.tar.xz"
            external.write_bytes(b"fixture")
            (folder / "goodbear-fixture.en-US.linux-x86_64.tar.xz").symlink_to(external)
            with self.assertRaisesRegex(BUILD.BuildError, "canonical object directory"):
                BUILD.find_base_package(context.objdir)


if __name__ == "__main__":
    unittest.main()
