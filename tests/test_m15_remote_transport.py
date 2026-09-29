#!/usr/bin/env python3
"""Focused fail-closed contracts for GB100-M15-01 local transport."""

from __future__ import annotations

import copy
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from host_build_context import HostBuildContext

SPEC = importlib.util.spec_from_file_location("m15_transport", ROOT / "tools" / "m15_remote_transport.py")
assert SPEC and SPEC.loader
TRANSPORT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TRANSPORT
SPEC.loader.exec_module(TRANSPORT)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RemoteTransportTest(unittest.TestCase):
    def setUp(self) -> None:
        # Fixtures intentionally mutate their source trees to exercise each
        # transport boundary. Production preparation calls the real Git guard.
        self.git_source_patcher = mock.patch.object(
            TRANSPORT, "require_clean_git_source", return_value="a" * 40)
        self.git_source_patcher.start()
        self.addCleanup(self.git_source_patcher.stop)

    def minimal_source_transport(self, directory: Path) -> tuple[Path, Path]:
        """A hash-valid source transport fixture; PKI tests use real M3 inputs."""
        manifest = {
            "schema_version": 1,
            "task": "GB100-M15-01",
            "source_commit": "a" * 40,
            "declared_inputs": [],
        }
        manifest_path = directory / "source-manifest.json"
        manifest_bytes = TRANSPORT.canonical_json(manifest)
        manifest_path.write_bytes(manifest_bytes)
        bundle_path = directory / "source-bundle.tar"
        with tarfile.open(bundle_path, "w") as archive:
            info = tarfile.TarInfo("source-manifest.json")
            info.size = len(manifest_bytes)
            archive.addfile(info, io.BytesIO(manifest_bytes))
        return manifest_path, bundle_path

    def test_production_ubuntu_objdir_is_accepted_by_host_build_context(self) -> None:
        contract = json.loads(
            (ROOT / "config" / "m15-01-remote-transport.json").read_text(encoding="utf-8")
        )
        invocation = contract["remote_workspaces"]["ubuntu-amd64"]["build_invocation"]
        objdir = Path(invocation[invocation.index("--objdir") + 1])

        self.assertFalse(objdir.is_absolute())
        self.assertEqual(objdir.parts[0], "artifacts")
        context = HostBuildContext.create(ROOT / objdir)
        self.assertEqual(context.objdir, (ROOT / objdir).resolve())

    def test_production_contract_preserves_local_coverage_owners_and_requests_full_lto(self) -> None:
        contract = json.loads(
            (ROOT / "config" / "m15-01-remote-transport.json").read_text(encoding="utf-8")
        )
        inputs = contract["source_inputs"]["declared_paths"]
        # Some test fixtures deliberately contain key-shaped values.  The
        # source-transport secret scanner must keep such test inputs local;
        # decision coverage runs in the source-authority checkout before the
        # materialized source marker is frozen and transferred.
        self.assertNotIn("tests", inputs)
        invocation = contract["remote_workspaces"]["ubuntu-amd64"]["build_invocation"]
        self.assertIn("--release-lto", invocation)
        windows = contract["remote_workspaces"]["windows-x64"]["build_invocation"]
        self.assertEqual(windows, ["./mach", "build", "-j4"])

    def fixture(self, directory: Path) -> tuple[Path, Path]:
        root = directory / "authority"
        for relative, content in {
            "config/firefox-baseline.json": json.dumps({
                "product": "Firefox Desktop / Gecko", "version": "999.1",
                "vcs": {"revision": "a" * 40},
                "source": {"archive_path": "source/firefox-999.1.source.tar.xz", "sha256": ""},
            }),
            "config/build.json": "{\"public\": true}\n",
            "config/m15-12-safebrowsing-build-input.json": json.dumps({
                "schema_version": 1, "task": "GB100-M15-12", "supplier": "Google Safe Browsing",
                "key_file_sha256": "b" * 64, "allowed_api_services": ["safebrowsing.googleapis.com"],
                "key_value_in_source": False, "key_value_in_build_logs": False,
                "key_embedded_in_browser_binary_by_design": True,
            }),
            "build/ubuntu/mozconfig": "ac_add_options --enable-ui-locale=ru\n",
            "tools/build_host_russian.py": "print('build')\n",
            "tools/build_windows_russian.py": "print('build')\n",
            "patches/series": "0001.patch\n",
            "patches/0001.patch": "diff --git a/a b/a\n",
            "overlay/browser.txt": "overlay\n",
            "artwork/final/m10-03/logo.txt": "art\n",
            "source/l10n/firefox-l10n/ru/browser/browser/appmenu.ftl": "menu = Меню\n",
            "source/l10n/firefox-l10n/ru/browser/browser/browser.ftl": "name = Good Bear\n",
            "source/l10n/firefox-l10n/ru/browser/browser/protectionsPanel.ftl": "panel = Защита\n",
            "source/l10n/firefox-l10n/ru/browser/browser/sitePermissions.ftl": "site = Сайт\n",
            "source/firefox-999.1.source.tar.xz": "upstream archive bytes\n",
        }.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        baseline_path = root / "config/firefox-baseline.json"
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        baseline["source"]["sha256"] = digest(root / "source/firefox-999.1.source.tar.xz")
        baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
        contract = {
            "schema_version": 1, "task": "GB100-M15-01",
            "source_authority": {"remote_connections": "не реализуются этим инструментом"},
            "source_inputs": {
                "baseline": "config/firefox-baseline.json",
                "declared_paths": ["config", "build", "tools", "patches/series", "overlay", "artwork/final/m10-03",
                                   "source/l10n/firefox-l10n/ru"],
                "ordered_patch_series": "patches/series", "upstream_archive_from_baseline": True,
            },
            "remote_build_inputs": {
                "safebrowsing": copy.deepcopy(TRANSPORT.SAFEBROWSING_INPUT),
                "russian_pki": {
                    "separate_hash_manifest_transport": True,
                    "logical_destination": "artifacts/certificates/build-inputs/current",
                    "m3_supply_chain_verifier": "tools/verify_m3_04_certificate_supply_chain.py",
                    "verify_before_build_environment": True,
                }
            },
            "remote_workspaces": {
                "ubuntu-amd64": {
                    "kind": "Ubuntu", "bootstrap_invocations": [["python3", "bootstrap.py"]],
                    "build_invocation": ["python3", "build.py"],
                },
                "windows-x64": {
                    "kind": "Windows", "bootstrap_invocations": [],
                    "build_invocation": ["python", "build.py"],
                },
            },
            "returned_result": {"required_result_file": "result.json", "required_prefixes": ["artifacts/", "logs/"]},
        }
        contract_path = root / "config/m15.json"
        contract_path.write_text(json.dumps(contract, ensure_ascii=False), encoding="utf-8")
        return root, contract_path

    def successful_result(self, destination: Path, directory: Path, platform: str = "ubuntu-amd64") -> Path:
        plan = json.loads((destination / "transport-plan.json").read_text(encoding="utf-8"))
        result = directory / "remote-result"
        (result / "artifacts").mkdir(parents=True)
        (result / "logs").mkdir()
        artifact = result / "artifacts/candidate.bin"
        log = result / "logs/build.log"
        artifact.write_text("candidate\n", encoding="utf-8")
        log.write_text("finished\n", encoding="utf-8")
        metadata = {
            "task": "GB100-M15-01", "platform": platform, "status": "succeeded",
            "source_manifest_sha256": plan["source_manifest_sha256"],
            "source_bundle_sha256": plan["source_bundle_sha256"],
            "artifacts": [{"path": "artifacts/candidate.bin", "sha256": digest(artifact)}],
            "logs": [{"path": "logs/build.log", "sha256": digest(log)}],
        }
        (result / "result.json").write_text(json.dumps(metadata), encoding="utf-8")
        return result

    def test_dry_run_creates_one_bound_plan_without_remote_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, contract = self.fixture(Path(temporary))
            destination = Path(temporary) / "dedicated-m15-output"
            TRANSPORT.dry_run(root, contract, destination)
            manifest = TRANSPORT.verify_prepared(destination)
            plan = json.loads((destination / "transport-plan.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["upstream"]["version"], "999.1")
            self.assertEqual(set(plan["platforms"]), {"ubuntu-amd64", "windows-x64"})
            for details in plan["platforms"].values():
                self.assertTrue(all(command["source_manifest_sha256"] == plan["source_manifest_sha256"]
                                    for command in details["remote_commands"]))
            self.assertNotIn("ssh", json.dumps(plan).lower())

    def test_source_freeze_requires_a_committed_clean_git_work_tree(self) -> None:
        self.git_source_patcher.stop()
        root = Path("/source-authority")
        with mock.patch.object(
            TRANSPORT.subprocess,
            "run",
            return_value=mock.Mock(returncode=0, stdout="true\n"),
        ):
            with self.assertRaisesRegex(TRANSPORT.TransportError, "existing Git commit"):
                TRANSPORT.require_clean_git_source(root)

        responses = (
            mock.Mock(returncode=0, stdout="true\n"),
            mock.Mock(returncode=0, stdout="a" * 40 + "\n"),
            mock.Mock(returncode=0, stdout=" M source.txt\n"),
        )
        with mock.patch.object(TRANSPORT.subprocess, "run", side_effect=responses):
            with self.assertRaisesRegex(TRANSPORT.TransportError, "clean Git work tree"):
                TRANSPORT.require_clean_git_source(root)

    def test_remote_transport_rejects_partial_or_empty_russian_l10n_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, contract = self.fixture(Path(temporary))
            data = json.loads(contract.read_text(encoding="utf-8"))
            data["source_inputs"]["declared_paths"].remove("source/l10n/firefox-l10n/ru")
            data["source_inputs"]["declared_paths"].append(
                "source/l10n/firefox-l10n/ru/browser/browser/browser.ftl")
            contract.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(TRANSPORT.TransportError, "complete Russian l10n tree"):
                TRANSPORT.prepare(root, contract, Path(temporary) / "partial")

        with tempfile.TemporaryDirectory() as temporary:
            root, contract = self.fixture(Path(temporary))
            (root / "source/l10n/firefox-l10n/ru/browser/browser/appmenu.ftl").write_text(
                "", encoding="utf-8")
            with self.assertRaisesRegex(TRANSPORT.TransportError, "empty Russian Fluent"):
                TRANSPORT.prepare(root, contract, Path(temporary) / "empty")

    def test_private_supplier_hash_is_bound_without_key_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, contract = self.fixture(Path(temporary))
            destination = Path(temporary) / "transport"
            TRANSPORT.prepare(root, contract, destination)
            manifest = TRANSPORT.verify_prepared(destination)
            binding = manifest["private_build_inputs"]["safebrowsing"]
            self.assertEqual(binding["key_file_sha256"], "b" * 64)
            self.assertEqual(binding["supplier_contract_sha256"],
                             digest(root / binding["supplier_contract"]))
            plan_path = destination / "transport-plan.json"
            plan = json.loads(plan_path.read_bytes())
            plan["private_build_inputs"]["safebrowsing"]["key_file_sha256"] = "c" * 64
            plan_path.write_text(json.dumps(plan))
            with self.assertRaisesRegex(TRANSPORT.TransportError, "private input binding"):
                TRANSPORT.verify_prepared(destination)

    def test_missing_or_unsafe_public_supplier_binding_rejected(self) -> None:
        for change in ("missing", "invalid-hash", "key-in-source", "extra-service"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root, contract = self.fixture(Path(temporary))
                supplier_path = root / TRANSPORT.SAFEBROWSING_INPUT["supplier_contract"]
                supplier = json.loads(supplier_path.read_bytes())
                if change == "missing":
                    supplier_path.unlink()
                else:
                    if change == "invalid-hash":
                        supplier["key_file_sha256"] = "not-a-digest"
                    elif change == "key-in-source":
                        supplier["key_value_in_source"] = True
                    else:
                        supplier["allowed_api_services"].append("other.googleapis.com")
                    supplier_path.write_text(json.dumps(supplier))
                with self.assertRaises(TRANSPORT.TransportError):
                    TRANSPORT.prepare(root, contract, Path(temporary) / "transport")

    def test_remote_transport_rejects_present_but_unverifiable_l10n_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, contract = self.fixture(Path(temporary))
            (root / "config/firefox-l10n-ru-lock.json").write_text(
                json.dumps({"schema_version": 1}), encoding="utf-8"
            )
            with self.assertRaisesRegex(TRANSPORT.TransportError, "Russian l10n reproducibility gate"):
                TRANSPORT.declared_files(root, TRANSPORT.load_contract(contract))

    def test_declared_tree_excludes_materialized_vcs_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input/.git").mkdir(parents=True)
            (root / "input/.git/config").write_text("private checkout state\n", encoding="utf-8")
            (root / "input/locale.ftl").write_text("visible = Да\n", encoding="utf-8")
            self.assertEqual(
                [path.relative_to(root).as_posix() for path in TRANSPORT.files_below(root, "input")],
                ["input/locale.ftl"],
            )

    def test_received_hash_valid_source_bundle_rejects_embedded_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, contract = self.fixture(Path(temporary))
            manifest = TRANSPORT.manifest_for(root, contract, TRANSPORT.load_contract(contract))
            target = root / "config/build.json"
            target.write_bytes(b"AIza" + b"C" * 35)
            entry = next(item for item in manifest["declared_inputs"] if item["path"] == "config/build.json")
            entry.update(sha256=digest(target), size=target.stat().st_size)
            manifest_path = Path(temporary) / "manifest.json"
            manifest_bytes = TRANSPORT.canonical_json(manifest)
            manifest_path.write_bytes(manifest_bytes)
            bundle = Path(temporary) / "bundle.tar"
            TRANSPORT.write_bundle(bundle, manifest_bytes, root, manifest)
            with self.assertRaisesRegex(TRANSPORT.TransportError, "секрет"):
                TRANSPORT.verify_bundle(root, manifest_path, bundle, digest(bundle), digest(manifest_path))

    def test_tampered_bundle_or_undeclared_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, contract = self.fixture(Path(temporary))
            destination = Path(temporary) / "dedicated-m15-output"
            TRANSPORT.prepare(root, contract, destination)
            bundle = destination / "source-bundle.tar"
            bundle.write_bytes(bundle.read_bytes() + b"tamper")
            with self.assertRaisesRegex(TRANSPORT.TransportError, "хеш source bundle"):
                TRANSPORT.verify_prepared(destination)
        with tempfile.TemporaryDirectory() as temporary:
            root, contract = self.fixture(Path(temporary))
            destination = Path(temporary) / "dedicated-m15-output"
            TRANSPORT.prepare(root, contract, destination)
            bundle = destination / "source-bundle.tar"
            with tarfile.open(bundle, "a") as archive:
                data = b"not declared"
                info = tarfile.TarInfo("source/extra.txt")
                info.size = len(data)
                archive.addfile(info, __import__("io").BytesIO(data))
            manifest = destination / "source-manifest.json"
            with self.assertRaisesRegex(TRANSPORT.TransportError, "необъявленный"):
                TRANSPORT.verify_bundle(root, manifest, bundle)

    def test_secret_input_never_enters_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, contract = self.fixture(Path(temporary))
            token = "github" + "_pat_abcdefghijklmnopqrstuvwxyz0123456789"
            (root / "config/token.txt").write_text(token, encoding="utf-8")
            with self.assertRaisesRegex(TRANSPORT.TransportError, "секрет"):
                TRANSPORT.prepare(root, contract, Path(temporary) / "dedicated-m15-output")

    def test_google_api_key_is_rejected_in_source_even_across_read_boundary(self) -> None:
        key = b"AIza" + b"A" * 35
        with tempfile.TemporaryDirectory() as temporary:
            root, contract = self.fixture(Path(temporary))
            path = root / "config/provider.txt"
            path.write_bytes(b"x" * (1024 * 1024 - 17) + key + b"\n")
            with self.assertRaisesRegex(TRANSPORT.TransportError, "секрет"):
                TRANSPORT.prepare(root, contract, Path(temporary) / "dedicated-m15-output")

    def test_embedded_browser_key_does_not_allow_a_key_in_returned_logs(self) -> None:
        key = b"AIza" + b"B" * 35
        with tempfile.TemporaryDirectory() as temporary:
            root, contract = self.fixture(Path(temporary))
            destination = Path(temporary) / "dedicated-m15-output"
            TRANSPORT.prepare(root, contract, destination)
            remote = self.successful_result(destination, Path(temporary))
            result_path = remote / "result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            artifact = remote / result["artifacts"][0]["path"]
            artifact.write_bytes(b"binary-fixture\x00" + key)
            result["artifacts"][0]["sha256"] = digest(artifact)
            self.assertEqual(len(TRANSPORT.result_files(remote, result)), 2)
            log = remote / result["logs"][0]["path"]
            log.write_bytes(b"x" * (1024 * 1024 - 9) + key)
            result["logs"][0]["sha256"] = digest(log)
            result_path.write_text(json.dumps(result), encoding="utf-8")
            with self.assertRaisesRegex(TRANSPORT.TransportError, "секрет"):
                TRANSPORT.collect_return(destination, "ubuntu-amd64", remote)
            self.assertFalse((destination / "returned").exists())

    def test_only_matching_successful_return_is_atomically_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, contract = self.fixture(Path(temporary))
            destination = Path(temporary) / "dedicated-m15-output"
            TRANSPORT.prepare(root, contract, destination)
            remote = self.successful_result(destination, Path(temporary))
            promoted = TRANSPORT.collect_return(destination, "ubuntu-amd64", remote)
            self.assertTrue((promoted / "artifacts/candidate.bin").is_file())
            self.assertTrue((promoted / "logs/build.log").is_file())

    def test_interrupted_or_secret_return_remains_unpromoted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, contract = self.fixture(Path(temporary))
            destination = Path(temporary) / "dedicated-m15-output"
            TRANSPORT.prepare(root, contract, destination)
            remote = self.successful_result(destination, Path(temporary))
            result_path = remote / "result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["status"] = "interrupted"
            result_path.write_text(json.dumps(result), encoding="utf-8")
            with self.assertRaisesRegex(TRANSPORT.TransportError, "неуспешная"):
                TRANSPORT.collect_return(destination, "ubuntu-amd64", remote)
            self.assertFalse((destination / "returned").exists())
            result["status"] = "succeeded"
            log = remote / "logs/build.log"
            token = "gh" + "p_abcdefghijklmnopqrstuvwxyz0123456789\n"
            log.write_text(token, encoding="utf-8")
            result["logs"][0]["sha256"] = digest(log)
            result_path.write_text(json.dumps(result), encoding="utf-8")
            with self.assertRaisesRegex(TRANSPORT.TransportError, "секрет"):
                TRANSPORT.collect_return(destination, "ubuntu-amd64", remote)
            self.assertFalse((destination / "returned").exists())

    def test_m3_verifier_loads_with_an_isolated_import_path(self) -> None:
        tools_directory = str((ROOT / "tools").resolve())
        original_path = list(sys.path)
        original_module = sys.modules.pop("project_temp", None)
        try:
            sys.path[:] = [entry for entry in sys.path if Path(entry).resolve() != Path(tools_directory)]
            verifier = TRANSPORT.load_m3_supply_chain_verifier(ROOT)
            self.assertTrue(callable(verifier.run))
            self.assertNotIn(tools_directory, sys.path)
        finally:
            sys.path[:] = original_path
            sys.modules.pop("project_temp", None)
            if original_module is not None:
                sys.modules["project_temp"] = original_module

    def test_pki_transport_is_bound_to_source_and_revalidated_by_m3(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "dedicated-m15-output"
            destination.mkdir()
            source_manifest, source_bundle = self.minimal_source_transport(destination)
            TRANSPORT.prepare_pki(ROOT, destination, source_manifest, source_bundle)
            manifest = TRANSPORT.verify_pki_prepared(
                ROOT, destination, source_manifest, source_bundle
            )
            self.assertEqual(manifest["destination"], TRANSPORT.PKI_INPUT_DIR.as_posix())
            self.assertEqual(
                manifest["source_manifest_sha256"], digest(source_manifest)
            )
            plan = json.loads(
                (destination / TRANSPORT.PKI_PLAN_NAME).read_text(encoding="utf-8")
            )
            self.assertEqual(plan["source_bundle_sha256"], digest(source_bundle))
            self.assertTrue((destination / TRANSPORT.PKI_BUNDLE_NAME).is_file())
            transport_archive = destination / TRANSPORT.PKI_TRANSPORT_ARCHIVE_NAME
            self.assertTrue(transport_archive.is_file())
            with tarfile.open(transport_archive, "r") as archive:
                self.assertEqual(
                    {member.name for member in archive.getmembers()},
                    {TRANSPORT.PKI_MANIFEST_NAME, TRANSPORT.PKI_BUNDLE_NAME, TRANSPORT.PKI_PLAN_NAME},
                )
                for member in archive.getmembers():
                    extracted = archive.extractfile(member)
                    self.assertIsNotNone(extracted)
                    self.assertEqual(extracted.read(), (destination / member.name).read_bytes())

    def test_pki_bundle_rejects_extra_member_after_hash_is_updated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "dedicated-m15-output"
            destination.mkdir()
            source_manifest, source_bundle = self.minimal_source_transport(destination)
            TRANSPORT.prepare_pki(ROOT, destination, source_manifest, source_bundle)
            bundle = destination / TRANSPORT.PKI_BUNDLE_NAME
            with tarfile.open(bundle, "a") as archive:
                info = tarfile.TarInfo("pki/extra.der")
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
            plan_path = destination / TRANSPORT.PKI_PLAN_NAME
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            plan["pki_bundle_sha256"] = digest(bundle)
            plan_path.write_bytes(TRANSPORT.canonical_json(plan))
            with self.assertRaisesRegex(TRANSPORT.TransportError, "undeclared"):
                TRANSPORT.verify_pki_prepared(ROOT, destination, source_manifest, source_bundle)

    def test_pki_transport_rejects_source_binding_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "dedicated-m15-output"
            destination.mkdir()
            source_manifest, source_bundle = self.minimal_source_transport(destination)
            TRANSPORT.prepare_pki(ROOT, destination, source_manifest, source_bundle)
            source_manifest.write_text(
                '{"task":"GB100-M15-01","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
                '"declared_inputs":[]}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(TRANSPORT.TransportError, "хеш source manifest"):
                TRANSPORT.verify_pki_prepared(ROOT, destination, source_manifest, source_bundle)


if __name__ == "__main__":
    unittest.main()
