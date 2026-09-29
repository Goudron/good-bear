#!/usr/bin/env python3
"""Focused fail-closed checks for M13-06 release evidence assembly."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m13_06_evidence", ROOT / "tools/assemble_m13_06_release_evidence.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class M1306EvidenceContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root / "candidate.tar.xz"
        self.bundle = self.root / "source-bundle.tar"
        self.source_manifest = self.root / "source-manifest.json"
        self.package = self.root / "candidate.deb"
        self.evidence = self.root / "package.evidence.json"
        self.identity = json.loads(MODULE.IDENTITY_PATH.read_text())
        self.baseline = json.loads(MODULE.BASELINE_PATH.read_text())
        self.baseline["source"]["sha256"] = MODULE.hashlib.sha256(b"upstream fixture").hexdigest()
        identity_path = self.root / "identity.json"
        baseline_path = self.root / "baseline.json"
        identity_path.write_text(json.dumps(self.identity))
        baseline_path.write_text(json.dumps(self.baseline))
        for name, value in (("IDENTITY_PATH", identity_path), ("BASELINE_PATH", baseline_path)):
            patcher = patch.object(MODULE, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for path in (self.archive, self.package):
            path.write_bytes(b"candidate fixture; not a browser")
        self.manifest = {
            "schema_version": 1, "task": "GB100-M15-01",
            "source_commit": "a" * 40,
            "upstream": {
                "product": self.baseline["product"], "version": self.baseline["version"],
                "revision": self.baseline["vcs"]["revision"],
                "archive": self.baseline["source"]["archive_path"],
                "archive_sha256": self.baseline["source"]["sha256"],
            },
            "declared_inputs": [{"path": self.baseline["source"]["archive_path"],
                                 "sha256": self.baseline["source"]["sha256"],
                                 "size": len(b"upstream fixture")}],
        }
        self.write_manifest_and_bundle()
        self.record = {
            "task": "GB100-M13-06", "candidate_status": "unsigned candidate; public release not implied",
            "platform": "ubuntu-amd64", "ubuntu_target": "24.04.4 LTS", "lto": "full", "locale": "ru",
            "version_pair": self.identity["version_pair"],
            "archive": self.archive.name, "archive_sha256": MODULE.sha256(self.archive),
            "package": self.package.name, "package_sha256": MODULE.sha256(self.package),
        }
        self.write_evidence()

    def write_manifest_and_bundle(self, payload: bytes = b"upstream fixture") -> None:
        self.source_manifest.write_text(json.dumps(self.manifest))
        with tarfile.open(self.bundle, "w") as archive:
            for name, data in (("source-manifest.json", self.source_manifest.read_bytes()),
                               ("source/" + self.baseline["source"]["archive_path"], payload)):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

    def write_evidence(self) -> None:
        self.record.update(source_manifest=self.source_manifest.name,
                           source_manifest_sha256=MODULE.sha256(self.source_manifest))
        self.evidence.write_text(json.dumps(self.record))

    def load_fixture(self) -> dict:
        return MODULE.load_inputs(self.archive, self.bundle, self.source_manifest, self.package, self.evidence)

    def test_rejects_package_evidence_that_does_not_bind_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "candidate.tar.xz"
            bundle = root / "source-bundle.tar"
            source_manifest = root / "source-manifest.json"
            package = root / "candidate.deb"
            evidence = root / "package.evidence.json"
            for path in (archive, bundle, package):
                path.write_bytes(b"test")
            source_manifest.write_text(json.dumps({
                "schema_version": 1, "task": "GB100-M15-01", "source_commit": "a" * 40,
                "upstream": {},
            }), encoding="utf-8")
            evidence.write_text(json.dumps({"archive": archive.name, "archive_sha256": "0" * 64}), encoding="utf-8")
            with self.assertRaisesRegex(MODULE.EvidenceError,
                                        "unexpected Good Bear|package evidence|frozen source"):
                MODULE.load_inputs(archive, bundle, source_manifest, package, evidence)

    def test_outputs_bind_current_baseline_and_retain_unsigned_boundary(self) -> None:
        destination = self.root / "output"
        manifest = MODULE.assemble(self.archive, self.bundle, self.source_manifest,
                                   self.package, self.evidence, destination)
        self.assertFalse(manifest["public_release_allowed"])
        self.assertIn("unsigned", manifest["candidate_status"])
        self.assertIn("disabled", manifest["application_updater"])
        self.assertEqual(manifest["version_pair"]["firefox"], self.baseline["version"])
        bom = json.loads((destination / "sbom.cdx.json").read_text())
        properties = {p["name"]: p["value"] for p in bom["metadata"]["component"]["properties"]}
        self.assertEqual(properties["goodbear:firefox-base-version"], self.baseline["version"])
        self.assertIn(f"Firefox {self.baseline['version']}", (destination / "SHA256SUMS").read_text())
        self.assertNotIn("155.0.1", (destination / "sbom.cdx.json").read_text())

    def test_rejects_stale_155_identity_even_with_matching_package_record(self) -> None:
        pair = self.identity["version_pair"]
        pair.update(firefox_base_version="155.0.1", canonical_about_ru="Good Bear 1.0 (Firefox 155.0.1)",
                    package_version="1.0+firefox155.0.1")
        MODULE.IDENTITY_PATH.write_text(json.dumps(self.identity))
        self.write_evidence()
        with self.assertRaisesRegex(MODULE.EvidenceError, "unexpected Good Bear"):
            self.load_fixture()

    def test_rejects_each_stale_upstream_binding(self) -> None:
        for key, value in (("version", "155.0.1"), ("revision", "0" * 40),
                           ("archive_sha256", "0" * 64), ("archive", "source/old.tar.xz")):
            with self.subTest(key=key):
                original = self.manifest["upstream"][key]
                self.manifest["upstream"][key] = value
                self.write_manifest_and_bundle()
                self.write_evidence()
                with self.assertRaisesRegex(MODULE.EvidenceError, "pinned Firefox baseline"):
                    self.load_fixture()
                self.manifest["upstream"][key] = original

    def test_rejects_tampered_source_bundle(self) -> None:
        self.write_manifest_and_bundle(b"tampered fixture")
        with self.assertRaisesRegex(MODULE.EvidenceError, "source bundle verification failed"):
            self.load_fixture()

    def test_rejects_tampered_browser_archive(self) -> None:
        self.archive.write_bytes(b"changed archive")
        with self.assertRaisesRegex(MODULE.EvidenceError, "bind the frozen archive"):
            self.load_fixture()

    def test_debian_packager_rejects_a_stale_source_manifest(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "m13_deb_fixture", ROOT / "tools/build_m13_06_ubuntu_deb.py")
        packager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packager)
        baseline = json.loads((ROOT / "config/firefox-baseline.json").read_text())
        self.manifest["upstream"]["archive_sha256"] = baseline["source"]["sha256"]
        self.source_manifest.write_text(json.dumps(self.manifest))
        self.assertEqual(packager.load_manifest(self.source_manifest), self.manifest)
        self.manifest["upstream"]["version"] = "155.0.1"
        self.source_manifest.write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(packager.PackageError, "pinned Firefox baseline"):
            packager.load_manifest(self.source_manifest)

    def test_failed_output_verification_does_not_promote_directory(self) -> None:
        destination = self.root / "output"
        with patch.object(MODULE, "verify_output", side_effect=MODULE.EvidenceError("injected output failure")):
            with self.assertRaisesRegex(MODULE.EvidenceError, "injected output failure"):
                MODULE.assemble(self.archive, self.bundle, self.source_manifest,
                                self.package, self.evidence, destination)
        self.assertFalse(destination.exists())

    def test_debian_validator_uses_the_nonempty_russian_resource_gate(self) -> None:
        source = (ROOT / "tools/build_m13_06_ubuntu_deb.py").read_text(encoding="utf-8")
        self.assertIn("REQUIRED_BROWSER_RUSSIAN_RESOURCES", source)
        self.assertIn("missing or empty Russian Fluent resource", source)


if __name__ == "__main__":
    unittest.main()
