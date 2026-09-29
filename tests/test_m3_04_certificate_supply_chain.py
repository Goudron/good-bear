#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "config/russian-pki-manifest.json"
SPEC = importlib.util.spec_from_file_location(
    "m3_04_supply_chain", ROOT / "tools/verify_m3_04_certificate_supply_chain.py"
)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class M304CertificateSupplyChainTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("openssl") is None:
            raise unittest.SkipTest("OpenSSL is required for M3-04 certificate tests")
        cls.base_manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="good-bear-m3-04-test-")
        self.root = Path(self.temporary.name)
        self.certificates: dict[str, bytes] = {}
        self.build_number = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def command(self, *args: str) -> None:
        subprocess.run(["openssl", *args], cwd=self.root, check=True, capture_output=True)

    def make_chain(self, suffix: str) -> tuple[str, str]:
        root_id = f"rotation_root_{suffix}"
        intermediate_id = f"rotation_intermediate_{suffix}"
        self.command(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{root_id}.key",
            "-out", f"{root_id}.pem", "-subj", f"/CN=Good Bear Rotation Root {suffix}", "-days", "30",
            "-addext", "basicConstraints=critical,CA:true,pathlen:1",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
        )
        self.command(
            "req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{intermediate_id}.key",
            "-out", f"{intermediate_id}.csr", "-subj", f"/CN=Good Bear Rotation Intermediate {suffix}",
        )
        extensions = self.root / f"{intermediate_id}.ext"
        extensions.write_text(
            "basicConstraints=critical,CA:true,pathlen:0\n"
            "keyUsage=critical,keyCertSign,cRLSign,digitalSignature\n",
            encoding="utf-8",
        )
        self.command(
            "x509", "-req", "-in", f"{intermediate_id}.csr", "-CA", f"{root_id}.pem",
            "-CAkey", f"{root_id}.key", "-CAcreateserial", "-out", f"{intermediate_id}.pem", "-days", "30",
            "-extfile", str(extensions),
        )
        for certificate_id in (root_id, intermediate_id):
            self.command("x509", "-in", f"{certificate_id}.pem", "-outform", "DER", "-out", f"{certificate_id}.der")
            self.certificates[certificate_id] = (self.root / f"{certificate_id}.der").read_bytes()
        return root_id, intermediate_id

    def make_non_ca_root(self) -> str:
        certificate_id = "non_ca_root"
        self.command(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{certificate_id}.key",
            "-out", f"{certificate_id}.pem", "-subj", "/CN=Good Bear Non-CA Root", "-days", "30",
            "-addext", "basicConstraints=critical,CA:false",
            "-addext", "keyUsage=critical,digitalSignature",
        )
        self.command("x509", "-in", f"{certificate_id}.pem", "-outform", "DER", "-out", f"{certificate_id}.der")
        self.certificates[certificate_id] = (self.root / f"{certificate_id}.der").read_bytes()
        return certificate_id

    def identity(self, certificate_id: str) -> dict[str, str]:
        certificate_hash, spki_hash = PROBE.certificate_identity(self.certificates[certificate_id])
        return {"certificate_der_sha256": certificate_hash, "spki_der_sha256": spki_hash}

    def manifest_and_records(self, chains: list[tuple[str, str]]) -> tuple[dict, dict[str, dict]]:
        manifest = copy.deepcopy(self.base_manifest)
        manifest["trust_anchors"] = []
        manifest["intermediates"] = []
        records: dict[str, dict] = {}
        for root_id, intermediate_id in chains:
            root_identity = self.identity(root_id)
            intermediate_identity = self.identity(intermediate_id)
            manifest["trust_anchors"].append(
                {"id": root_id, "role": "trust_anchor", "identity": root_identity, "provenance_id": root_id}
            )
            manifest["intermediates"].append(
                {
                    "id": intermediate_id, "role": "intermediate", "identity": intermediate_identity,
                    "chains_to_anchor_identity": root_identity, "provenance_id": intermediate_id,
                }
            )
            for certificate_id, role, identity in (
                (root_id, "trust_anchor", root_identity),
                (intermediate_id, "intermediate", intermediate_identity),
            ):
                records[certificate_id] = {
                    "id": certificate_id, "role": role, "source_payload_sha256": hashlib.sha256(
                        self.certificates[certificate_id]
                    ).hexdigest(), **identity,
                }
        return manifest, records

    def build_inputs(self, manifest: dict, records: dict[str, dict]) -> Path:
        self.build_number += 1
        build = self.root / f"build-inputs-{self.build_number}"
        build.mkdir()
        entries = []
        for item, role in PROBE.expected_entries(manifest):
            certificate_id = item["id"]
            relative = Path(role) / f"{certificate_id}.der"
            target = build / relative
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(self.certificates[certificate_id])
            entries.append(
                {
                    "id": certificate_id, "role": role, "path": relative.as_posix(),
                    "source_payload_sha256": records[certificate_id]["source_payload_sha256"], **item["identity"],
                }
            )
        (build / "build-inputs.json").write_text(
            json.dumps(
                {
                    "schema_version": 1, "task": "GB100-M3-03", "source_contract_sha256": "d" * 64,
                    "runtime_certificate_download": False, "certificates": entries,
                }
            ),
            encoding="utf-8",
        )
        return build

    def validate(self, build: Path, manifest: dict, records: dict[str, dict]) -> None:
        PROBE.validate_build_inputs(build, manifest, records)

    def test_parses_pinned_der_and_accepts_multiple_reviewed_rotation_anchors(self) -> None:
        first = self.make_chain("one")
        second = self.make_chain("two")
        manifest, records = self.manifest_and_records([first, second])
        self.validate(self.build_inputs(manifest, records), manifest, records)

    def test_rotation_removal_accepts_retired_review_record_but_not_new_unreviewed_anchor(self) -> None:
        first = self.make_chain("one")
        second = self.make_chain("two")
        manifest, records = self.manifest_and_records([first, second])
        manifest["trust_anchors"] = [manifest["trust_anchors"][1]]
        manifest["intermediates"] = [manifest["intermediates"][1]]
        self.validate(self.build_inputs(manifest, records), manifest, records)

        unreviewed = copy.deepcopy(manifest)
        third = self.make_chain("three")
        root_identity = self.identity(third[0])
        unreviewed["trust_anchors"].append(
            {"id": third[0], "role": "trust_anchor", "identity": root_identity, "provenance_id": third[0]}
        )
        with self.assertRaisesRegex(PROBE.SupplyChainError, "unreviewed active certificate"):
            PROBE.validate_reviewed_rotation(unreviewed, records)

    def test_rejects_byte_replacement_and_same_name_fake_root(self) -> None:
        chain = self.make_chain("one")
        manifest, records = self.manifest_and_records([chain])
        build = self.build_inputs(manifest, records)
        (build / "trust_anchor" / f"{chain[0]}.der").write_bytes(b"not DER")
        with self.assertRaisesRegex(PROBE.SupplyChainError, "certificate parsing failed"):
            self.validate(build, manifest, records)

        fake = self.make_chain("fake")
        build = self.build_inputs(manifest, records)
        (build / "trust_anchor" / f"{chain[0]}.der").write_bytes(self.certificates[fake[0]])
        with self.assertRaisesRegex(PROBE.SupplyChainError, "DER-to-manifest identity mismatch"):
            self.validate(build, manifest, records)

    def test_rejects_manifest_drift_and_intermediate_promotion(self) -> None:
        chain = self.make_chain("one")
        manifest, records = self.manifest_and_records([chain])
        drifted = copy.deepcopy(manifest)
        drifted["trust_anchors"][0]["identity"]["certificate_der_sha256"] = "a" * 64
        with self.assertRaisesRegex(PROBE.SupplyChainError, "reviewed certificate identity drift"):
            self.validate(self.build_inputs(manifest, records), drifted, records)

        promoted = copy.deepcopy(manifest)
        promoted["trust_anchors"] = [
            {
                "id": chain[1], "role": "trust_anchor", "identity": self.identity(chain[1]),
                "provenance_id": chain[1],
            }
        ]
        promoted["intermediates"] = []
        promoted_records = copy.deepcopy(records)
        promoted_records[chain[1]]["role"] = "trust_anchor"
        with self.assertRaisesRegex(PROBE.SupplyChainError, "not self-issued"):
            self.validate(self.build_inputs(promoted, promoted_records), promoted, promoted_records)

    def test_rejects_reviewed_non_ca_anchor_on_basic_constraints(self) -> None:
        certificate_id = self.make_non_ca_root()
        identity = self.identity(certificate_id)
        manifest = copy.deepcopy(self.base_manifest)
        manifest["trust_anchors"] = [
            {"id": certificate_id, "role": "trust_anchor", "identity": identity, "provenance_id": certificate_id}
        ]
        manifest["intermediates"] = []
        records = {
            certificate_id: {
                "id": certificate_id, "role": "trust_anchor",
                "source_payload_sha256": hashlib.sha256(self.certificates[certificate_id]).hexdigest(), **identity,
            }
        }
        with self.assertRaisesRegex(PROBE.SupplyChainError, "CA basic constraints"):
            self.validate(self.build_inputs(manifest, records), manifest, records)

    def test_rejects_test_anchor_leakage_into_production_inputs(self) -> None:
        chain = self.make_chain("one")
        manifest, records = self.manifest_and_records([chain])
        build = self.build_inputs(manifest, records)
        leaked = build / "trust_anchor" / "test_anchor.der"
        leaked.write_bytes(self.certificates[chain[0]])
        with self.assertRaisesRegex(PROBE.SupplyChainError, "test-anchor leakage"):
            self.validate(build, manifest, records)

    def test_production_contract_is_bound_to_reviewed_non_test_inputs(self) -> None:
        manifest, records, digest = PROBE.load_production_contract()
        self.assertEqual(len(digest), 64)
        self.assertEqual(
            {entry["provenance_id"] for entry, _ in PROBE.expected_entries(manifest)}, set(records)
        )
        self.assertTrue(all("test" not in certificate_id for certificate_id in records))


if __name__ == "__main__":
    unittest.main()
