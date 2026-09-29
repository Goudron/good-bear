#!/usr/bin/env python3
"""Native preflight proves inputs only; it cannot authorize a product build."""

from __future__ import annotations

import argparse
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("m15_cloud_windows_preflight", ROOT / "tools/preflight_m15_cloud_windows.py")
assert SPEC and SPEC.loader
PREFLIGHT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREFLIGHT)


class NativeCloudPreflightTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.lock = json.loads((ROOT / "config/m15-03-windows-toolchain-lock.json").read_text(encoding="utf-8"))
        self.baseline = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))

    def write(self, relative: str, content: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def fixture_source(self):
        baseline = self.write("config/firefox-baseline.json", json.dumps(self.baseline))
        self.write("config/m15-12-safebrowsing-build-input.json", "{\"test\":true}\\n")
        self.write("config/m15-03-windows-toolchain-lock.json", json.dumps(self.lock))
        self.write("build/windows/mozconfig.release-lto", (ROOT / "build/windows/mozconfig.release-lto").read_text())
        for relative in PREFLIGHT.REQUIRED_PYTHON_OWNERS:
            self.write(relative, "# frozen test wrapper\n")
        self.write("patches/series", "")
        for relative in PREFLIGHT.transport.REQUIRED_RUSSIAN_L10N:
            self.write(relative, "test-russian-message = Проверка\n")
        entries = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file():
                entries.append({"path": path.relative_to(self.root).as_posix(), "size": path.stat().st_size,
                                "sha256": PREFLIGHT.sha256(path)})
        _, archive, source_pin = PREFLIGHT.materializer.baseline_values(self.baseline, baseline)
        source = archive.parent / "worktrees" / PREFLIGHT.materializer.archive_root_name(self.baseline["version"])
        source.mkdir(parents=True)
        version_file = source / "browser/config/version.txt"
        version_file.parent.mkdir(parents=True)
        version_file.write_text(self.baseline["version"], encoding="utf-8")
        marker = {"version": self.baseline["version"], "baseline_config_sha256": PREFLIGHT.sha256(baseline),
                  "source_sha256": source_pin["sha256"], "source_sha512": source_pin["sha512"], "patches": []}
        (source / ".good-bear-materialization.json").write_text(json.dumps(marker), encoding="utf-8")
        manifest = {"declared_inputs": entries, "upstream": {
            "product": self.baseline["product"], "version": self.baseline["version"],
            "revision": self.baseline["vcs"]["revision"], "archive": source_pin["archive_path"],
            "archive_sha256": source_pin["sha256"],
        }}
        return source, manifest

    def verify_fixture(self, source, manifest):
        with patch.object(PREFLIGHT.transport, "verify_bundle", return_value=manifest) as verified:
            result = PREFLIGHT.verify_frozen_source(self.root, source, self.root / "manifest.json",
                                                    self.root / "bundle.tar", "a" * 64, "b" * 64)
        self.assertEqual(verified.call_args.args[-2:], ("b" * 64, "a" * 64))
        return result

    def test_frozen_current_source_and_real_extracted_bytes_pass(self) -> None:
        source, manifest = self.fixture_source()
        evidence = self.verify_fixture(source, manifest)
        self.assertEqual(evidence["firefox_version"], "156.0")
        self.assertEqual(evidence["manifest_sha256"], "a" * 64)

    def test_modified_extracted_input_is_rejected_even_after_bundle_verification(self) -> None:
        source, manifest = self.fixture_source()
        self.write("patches/series", "unreviewed.patch\n")
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "extracted input differs"):
            self.verify_fixture(source, manifest)

    def test_hash_bound_source_delta_permits_only_its_exact_allowlisted_replacements(self) -> None:
        source, manifest = self.fixture_source()
        replacements = []
        for relative in sorted(PREFLIGHT.SOURCE_DELTA_PATHS):
            original = next(item for item in manifest["declared_inputs"] if item["path"] == relative)
            path = self.root / relative
            path.write_text("# reviewed delta " + relative + "\n", encoding="utf-8")
            replacements.append({"path": relative, "base_sha256": original["sha256"], "base_size": original["size"],
                                 "sha256": PREFLIGHT.sha256(path), "size": path.stat().st_size})
        record = {"schema_version": 1, "kind": "goodbear-m15-03-source-overlay",
                  "base_manifest_sha256": "a" * 64, "base_bundle_sha256": "b" * 64,
                  "replacements": replacements}
        self.write(PREFLIGHT.SOURCE_DELTA_RECORD, json.dumps(record))
        evidence = self.verify_fixture(source, manifest)
        self.assertEqual(evidence["source_delta"]["replacements"], sorted(PREFLIGHT.SOURCE_DELTA_PATHS))
        (self.root / "tools/windows_offline_worker.py").write_text("# tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "extracted input differs"):
            self.verify_fixture(source, manifest)

    def test_source_delta_cannot_replace_an_unapproved_owner(self) -> None:
        source, manifest = self.fixture_source()
        original = next(item for item in manifest["declared_inputs"] if item["path"] == "tools/project_temp.py")
        self.write(PREFLIGHT.SOURCE_DELTA_RECORD, json.dumps({
            "schema_version": 1, "kind": "goodbear-m15-03-source-overlay",
            "base_manifest_sha256": "a" * 64, "base_bundle_sha256": "b" * 64,
            "replacements": [{"path": "tools/project_temp.py", "base_sha256": original["sha256"],
                              "base_size": original["size"], "sha256": original["sha256"],
                              "size": original["size"]}],
        }))
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "replacement scope"):
            self.verify_fixture(source, manifest)

    def test_source_delta_rejects_an_incomplete_allowlist(self) -> None:
        source, manifest = self.fixture_source()
        relative = "config/m15-12-safebrowsing-build-input.json"
        original = next(item for item in manifest["declared_inputs"] if item["path"] == relative)
        self.write(PREFLIGHT.SOURCE_DELTA_RECORD, json.dumps({
            "schema_version": 1, "kind": "goodbear-m15-03-source-overlay",
            "base_manifest_sha256": "a" * 64, "base_bundle_sha256": "b" * 64,
            "replacements": [{"path": relative, "base_sha256": original["sha256"],
                              "base_size": original["size"], "sha256": original["sha256"],
                              "size": original["size"]}],
        }))
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "replacement scope"):
            self.verify_fixture(source, manifest)

    def test_stale_source_manifest_is_rejected(self) -> None:
        source, manifest = self.fixture_source()
        manifest["upstream"]["version"] = "155.0.1"
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "manifest and current Firefox baseline differ"):
            self.verify_fixture(source, manifest)

    def test_wrong_materialization_marker_is_rejected(self) -> None:
        source, manifest = self.fixture_source()
        marker = source / ".good-bear-materialization.json"
        value = json.loads(marker.read_text())
        value["baseline_config_sha256"] = "0" * 64
        marker.write_text(json.dumps(value))
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "marker does not bind"):
            self.verify_fixture(source, manifest)

    def test_snapshot_without_current_wrapper_cannot_pass(self) -> None:
        source, manifest = self.fixture_source()
        manifest["declared_inputs"] = [item for item in manifest["declared_inputs"]
                                       if item["path"] != "tools/preflight_m15_cloud_windows.py"]
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "snapshot lacks"):
            self.verify_fixture(source, manifest)

    def test_cached_archives_require_exact_bytes_and_do_not_fetch(self) -> None:
        cache = self.root / "cache"
        cache.mkdir()
        for component in self.lock["components"]:
            content = component["id"].encode()
            component["sha256"] = hashlib.sha256(content).hexdigest()
            (cache / PREFLIGHT.cached_filename(component)).write_bytes(content)
        verified = PREFLIGHT.verify_cached_toolchain(self.lock, cache)
        self.assertEqual(len(verified), 11)
        (cache / PREFLIGHT.cached_filename(self.lock["components"][0])).write_bytes(b"tampered")
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "cache hash mismatch"):
            PREFLIGHT.verify_cached_toolchain(self.lock, cache)

    def test_undeclared_python_sibling_and_extension_are_rejected(self) -> None:
        source, manifest = self.fixture_source()
        for relative in ("tools/shadow.py", "tools/shadow.pyd", "tools/package/__init__.py"):
            with self.subTest(relative=relative):
                path = self.write(relative, "unreviewed import\n")
                with self.assertRaisesRegex(PREFLIGHT.PreflightError, "undeclared Python import"):
                    self.verify_fixture(source, manifest)
                path.unlink()

    def test_declaring_bytecode_does_not_authorize_it(self) -> None:
        source, manifest = self.fixture_source()
        path = self.write("tools/__pycache__/project_temp.cpython-312.pyc", "unreviewed cache\n")
        for declared in (False, True):
            with self.subTest(declared=declared):
                if declared:
                    manifest["declared_inputs"].append({
                        "path": path.relative_to(self.root).as_posix(),
                        "size": path.stat().st_size, "sha256": PREFLIGHT.sha256(path),
                    })
                with self.assertRaisesRegex(PREFLIGHT.PreflightError, "source bytecode"):
                    self.verify_fixture(source, manifest)

    def test_import_tree_rejects_reparse_directory_before_descent(self) -> None:
        source, manifest = self.fixture_source()
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "tools/package").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "reparse point"):
            self.verify_fixture(source, manifest)

    def test_import_tree_checks_declared_helper_bytes_and_case_collisions(self) -> None:
        _, manifest = self.fixture_source()
        entries = manifest["declared_inputs"]
        self.write("tools/project_temp.py", "changed trusted import\n")
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "Python import bytes differ"):
            PREFLIGHT.verify_python_import_tree(self.root, entries)
        duplicate = {**next(item for item in entries if item["path"] == "tools/project_temp.py"),
                     "path": "tools/PROJECT_TEMP.py"}
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "case-ambiguous"):
            PREFLIGHT.verify_python_import_tree(self.root, [*entries, duplicate])

    def test_toolchain_family_and_network_policy_cannot_drift(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["network_policy"]["build_after_source_freeze"] = "allowed"
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "network policy changed"):
            PREFLIGHT.components(changed)

    def test_version_prefix_does_not_accept_another_patch_version(self) -> None:
        self.assertTrue(PREFLIGHT.version_matches("clang version 22.1.8 (pinned)", "clang version 22.1.8"))
        self.assertFalse(PREFLIGHT.version_matches("clang version 22.1.80", "clang version 22.1.8"))

    def test_child_process_environment_drops_runner_credentials(self) -> None:
        with patch.dict(PREFLIGHT.os.environ, {"ACTIONS_RUNTIME_TOKEN": "not-real", "GH_TOKEN": "not-real",
                                               "SystemRoot": r"C:\Windows"}, clear=True):
            environment = PREFLIGHT.native_environment()
        self.assertNotIn("ACTIONS_RUNTIME_TOKEN", environment)
        self.assertNotIn("GH_TOKEN", environment)
        self.assertEqual(environment["SystemRoot"], r"C:\Windows")
        self.assertTrue(environment["PATH"].startswith(r"C:\GoodBear\tools\firefox156-toolchains\mozmake;C:\GoodBear\tools\firefox156-toolchains\nsis;"))

    def installed_fixture(self, *, wrong_python=False, missing_mozmake=False):
        tools = self.root / "tools"
        self.lock["install_root"] = str(tools)
        pinned = PREFLIGHT.components(self.lock)
        expected_vs_installation = pinned["visual-studio-build-tools"].get(
            "installation_version", pinned["visual-studio-build-tools"]["version"])
        self.write("toolchain-evidence.json", json.dumps({
            "build_tools": expected_vs_installation, "msvc": "14.44.12345",
        }))
        outputs = {
            "python.exe": "Python " + ("0.0" if wrong_python else pinned["python"]["version"]),
            "git.exe": "git version " + pinned["git-for-windows"]["version"],
            "rustc.exe": "rustc 1.90.0 (test)", "cargo.exe": "cargo 1.90.0 (test)",
            "node.exe": "v" + pinned["node"]["version"],
            "nasm.exe": "NASM version " + pinned["nasm"]["version"] + " compiled test",
            "clang-cl.exe": "clang version " + pinned["llvm"]["version"],
        }

        def probe(command, environment):
            if command[0].endswith("vswhere.exe"):
                return expected_vs_installation if command[-1] == "installationVersion" else str(self.root / "vs-buildtools")
            return next(output for filename, output in outputs.items() if command[0].endswith(filename))

        stack = ExitStack()
        stack.enter_context(patch.object(PREFLIGHT.sys, "executable", str(tools / "Python312/python.exe")))
        stack.enter_context(patch.object(PREFLIGHT, "probe", side_effect=probe))
        stack.enter_context(patch.object(PREFLIGHT, "sha256", return_value="c" * 64))
        stack.enter_context(patch.object(Path, "is_file", lambda path: not (missing_mozmake and str(path).endswith("mozmake.exe"))))
        stack.enter_context(patch.object(Path, "is_dir", return_value=True))
        stack.enter_context(patch.object(Path, "iterdir", return_value=iter([self.root / "nsis-fixture"])))
        return stack

    def test_installed_tools_are_probed_against_the_reviewed_bootstrap(self) -> None:
        with self.installed_fixture():
            observed = PREFLIGHT.verify_installed_tools(self.lock, {})
        self.assertEqual(len(observed["executables"]), 7)
        self.assertTrue(observed["installed_executable_hashes_are_observations_not_new_trust_pins"])

    def test_changed_installed_version_is_rejected(self) -> None:
        with self.installed_fixture(wrong_python=True):
            with self.assertRaisesRegex(PREFLIGHT.PreflightError, "version differs: python"):
                PREFLIGHT.verify_installed_tools(self.lock, {})

    def test_missing_native_packaging_tool_is_rejected(self) -> None:
        with self.installed_fixture(missing_mozmake=True):
            with self.assertRaisesRegex(PREFLIGHT.PreflightError, "prerequisite is absent"):
                PREFLIGHT.verify_installed_tools(self.lock, {})

    def test_linux_cannot_claim_a_native_preflight(self) -> None:
        with patch.object(PREFLIGHT.sys, "platform", "linux"):
            with self.assertRaisesRegex(PREFLIGHT.PreflightError, "real Windows runner"):
                PREFLIGHT.run(argparse.Namespace())

    def test_cli_failure_records_no_product_artifact_or_native_success(self) -> None:
        report = self.root / "preflight.json"
        command = ["preflight", "--manifest", str(self.root / "manifest"), "--bundle", str(self.root / "bundle"),
                   "--expected-manifest-sha256", "a" * 64, "--expected-bundle-sha256", "b" * 64,
                   "--report", str(report)]
        with patch.object(PREFLIGHT.sys, "argv", command), patch.object(PREFLIGHT.sys, "platform", "linux"):
            self.assertEqual(PREFLIGHT.main(), 1)
        result = json.loads(report.read_text())
        self.assertFalse(result["preflight_passed"])
        self.assertFalse(result["execution_allowed"])
        self.assertEqual(result["product_artifacts"], [])

    def test_successful_preflight_does_not_authorize_or_claim_compilation(self) -> None:
        self.write("config/m15-03-windows-toolchain-lock.json", json.dumps(self.lock))
        args = argparse.Namespace(manifest=self.root / "manifest", bundle=self.root / "bundle",
                                  expected_manifest_sha256="a" * 64, expected_bundle_sha256="b" * 64)
        with patch.object(PREFLIGHT, "ROOT", self.root), patch.object(PREFLIGHT.sys, "platform", "win32"), \
                patch.object(PREFLIGHT, "verify_frozen_source", return_value={}), \
                patch.object(PREFLIGHT, "verify_cached_toolchain", return_value={}), \
                patch.object(PREFLIGHT, "verify_installed_tools", return_value={}), \
                patch.object(PREFLIGHT.subprocess, "run", return_value=argparse.Namespace(returncode=0)) as native:
            result = PREFLIGHT.run(args)
        self.assertTrue(result["preflight_passed"])
        self.assertFalse(result["build_executed"])
        self.assertFalse(result["execution_allowed"])
        self.assertEqual(result["product_artifacts"], [])
        command = native.call_args.args[0]
        self.assertEqual(command[1:6], ["-I", "-S", "-B", "-u", "-X"])
        self.assertIn(str(self.root / "tools/verify_m3_04_certificate_supply_chain.py"), command)
        self.assertEqual(len(result["execution_blockers"]), 2)

    def test_m3_failure_blocks_preflight(self) -> None:
        self.write("config/m15-03-windows-toolchain-lock.json", json.dumps(self.lock))
        args = argparse.Namespace(manifest=self.root / "manifest", bundle=self.root / "bundle",
                                  expected_manifest_sha256="a" * 64, expected_bundle_sha256="b" * 64)
        with patch.object(PREFLIGHT, "ROOT", self.root), patch.object(PREFLIGHT.sys, "platform", "win32"), \
                patch.object(PREFLIGHT, "verify_frozen_source", return_value={}), \
                patch.object(PREFLIGHT, "verify_cached_toolchain", return_value={}), \
                patch.object(PREFLIGHT, "verify_installed_tools", return_value={}), \
                patch.object(PREFLIGHT.subprocess, "run", return_value=argparse.Namespace(returncode=1)):
            with self.assertRaisesRegex(PREFLIGHT.PreflightError, "M3-04 rejected"):
                PREFLIGHT.run(args)


if __name__ == "__main__":
    unittest.main()
