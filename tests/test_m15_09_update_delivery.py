#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m15_09_update_delivery", ROOT / "tools" / "verify_m15_09_update_delivery.py"
)
assert SPEC and SPEC.loader
DELIVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DELIVERY)


class UpdateDeliveryContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = DELIVERY.load(ROOT / "config/m15-09-update-delivery-contract.json")
        self.manifest = {
            "tag": "goodbear-1.1-firefox155.0.2",
            "version": "1.1",
            "deb_filename": "goodbear-browser_1.1+firefox155.0.2-1_amd64.deb",
            "deb_sha256": "a" * 64,
            "deb_url": "https://github.com/good-bear/browser/releases/download/"
                       "goodbear-1.1-firefox155.0.2/"
                       "goodbear-browser_1.1+firefox155.0.2-1_amd64.deb",
        }

    def test_repository_contract_remains_blocked(self) -> None:
        DELIVERY.verify(ROOT)

    def test_version_pinned_github_release_manifest_and_command_are_accepted(self) -> None:
        DELIVERY.validate_ubuntu_release_manifest(self.manifest)
        command = DELIVERY.render_ubuntu_command(self.manifest)
        self.assertIn("sha256sum -c - && sudo apt install ./", command)
        DELIVERY.validate_ubuntu_command(command, self.manifest)

    def test_latest_floating_and_parameterized_urls_are_rejected(self) -> None:
        cases = (
            "https://github.com/good-bear/browser/releases/latest/download/"
            "goodbear-browser_1.1+firefox155.0.2-1_amd64.deb",
            "https://github.com/good-bear/browser/raw/main/"
            "goodbear-browser_1.1+firefox155.0.2-1_amd64.deb",
            self.manifest["deb_url"] + "?download=1",
            self.manifest["deb_url"] + "#asset",
            self.manifest["deb_url"].replace("github.com", "github.com:not-a-port"),
        )
        for url in cases:
            with self.subTest(url=url):
                manifest = dict(self.manifest, deb_url=url)
                with self.assertRaisesRegex(DELIVERY.DeliveryContractError, "version-pinned"):
                    DELIVERY.validate_ubuntu_release_manifest(manifest)

    def test_wrong_tag_version_filename_and_hash_shapes_are_rejected(self) -> None:
        cases = (
            ("tag", "goodbear-latest-firefox155.0.2", "tag"),
            ("version", "1.1-rc1", "version"),
            ("deb_filename", "goodbear-browser_1.1_amd64.deb", "filename"),
            ("deb_filename", "goodbear-browser_1.1+firefox155.0.1-1_amd64.deb", "filename"),
            ("deb_sha256", "A" * 64, "SHA-256"),
            ("deb_sha256", "a" * 63, "SHA-256"),
        )
        for field, value, error in cases:
            with self.subTest(field=field, value=value):
                manifest = dict(self.manifest, **{field: value})
                with self.assertRaisesRegex(DELIVERY.DeliveryContractError, error):
                    DELIVERY.validate_ubuntu_release_manifest(manifest)

    def test_privilege_escalation_before_checksum_is_rejected(self) -> None:
        command = DELIVERY.render_ubuntu_command(self.manifest)
        unsafe = command.replace(" && printf", " && sudo apt install ./unsafe.deb && printf")
        with self.assertRaisesRegex(DELIVERY.DeliveryContractError, "privileges before SHA-256"):
            DELIVERY.validate_ubuntu_command(unsafe, self.manifest)

    def test_command_cannot_add_an_unreviewed_action_after_verification(self) -> None:
        command = DELIVERY.render_ubuntu_command(self.manifest) + " && dpkg --force-overwrite -i unsafe.deb"
        with self.assertRaisesRegex(DELIVERY.DeliveryContractError, "exactly download"):
            DELIVERY.validate_ubuntu_command(command, self.manifest)

    def test_windows_ready_without_signing_evidence_is_rejected(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["windows"]["status"] = "ready"
        with self.assertRaisesRegex(DELIVERY.DeliveryContractError, "without signing evidence"):
            DELIVERY.validate_contract(changed)

    def test_claimed_windows_evidence_does_not_override_block(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["windows"].update({
            "status": "ready",
            "signing_evidence": {
                "approved_authority": "claimed authority",
                "metadata_signature": "claimed metadata signature",
                "complete_mar_signature": "claimed MAR signature",
                "key_rotation_record": "claimed rotation record",
            },
        })
        with self.assertRaisesRegex(DELIVERY.DeliveryContractError, "remains blocked"):
            DELIVERY.validate_contract(changed)


if __name__ == "__main__":
    unittest.main()
