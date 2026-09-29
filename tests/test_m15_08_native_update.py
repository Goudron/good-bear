#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m15_08_native_update", ROOT / "tools/verify_m15_08_native_update.py"
)
assert SPEC and SPEC.loader
UPDATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPDATE)


class NativeUpdateContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = UPDATE.load(ROOT / "config/m15-08-native-update-contract.json")
        self.installed = dict(product="Good Bear", channel="goodbear-release",
                              platform="win64", product_version="1.0",
                              firefox_base_version="155.0.1")
        self.offer = dict(product="Good Bear", channel="goodbear-release",
                          platform="win64", product_version="1.1",
                          firefox_base_version="155.0.2", app_version="155.0.2",
                          mar_product_version="155.0.2", mar_type="complete",
                          release_tag="goodbear-1.1-firefox155.0.2",
                          metadata_url="https://github.com/owner/repo/releases/download/"
                                       "goodbear-1.1-firefox155.0.2/update.xml",
                          mar_url="https://github.com/owner/repo/releases/download/"
                                  "goodbear-1.1-firefox155.0.2/update.mar",
                          mar_sha512=hashlib.sha512(b"test MAR bytes").hexdigest())

    def test_repository_remains_blocked(self) -> None:
        UPDATE.verify(ROOT)

    def test_goodbear_mar_uses_pinned_public_certificates(self) -> None:
        UPDATE.verify_mar_public_cert_binding(ROOT)

    def test_goodbear_mar_rejects_mozilla_or_swapped_certificates(self) -> None:
        original_read_text = Path.read_text
        mozbuild_path = UPDATE.FIREFOX_SOURCE / "toolkit/mozapps/update/updater/moz.build"

        def read_with_mozilla_cert(path: Path, *args: object, **kwargs: object) -> str:
            value = original_read_text(path, *args, **kwargs)
            if path == mozbuild_path:
                return value.replace('primary_cert.inputs += ["goodbear_mar_primary.der"]',
                                     'primary_cert.inputs += ["release_primary.der"]')
            return value

        with patch.object(Path, "read_text", read_with_mozilla_cert):
            with self.assertRaisesRegex(UPDATE.ContractError, "must select its own certificates"):
                UPDATE.verify_mar_public_cert_binding(ROOT)

        original_read_bytes = Path.read_bytes
        selected_primary = mozbuild_path.parent / "goodbear_mar_primary.der"
        selected_backup = mozbuild_path.parent / "goodbear_mar_backup.der"

        def read_with_swapped_cert(path: Path) -> bytes:
            if path == selected_primary:
                return original_read_bytes(selected_backup)
            return original_read_bytes(path)

        with patch.object(Path, "read_bytes", read_with_swapped_cert):
            with self.assertRaisesRegex(UPDATE.ContractError, "differs from the pinned"):
                UPDATE.verify_mar_public_cert_binding(ROOT)

    def test_repository_rejects_previous_firefox_version_pair(self) -> None:
        original_load = UPDATE.load
        identity = original_load(ROOT / "config/product-identity.json")
        for stale_contract, stale_identity in ((True, False), (False, True), (True, True)):
            with self.subTest(contract=stale_contract, identity=stale_identity):
                contract = copy.deepcopy(self.contract)
                product = copy.deepcopy(identity)
                if stale_contract:
                    contract["version_pair"]["firefox_base"] = "155.0.1"
                if stale_identity:
                    product["version_pair"]["firefox_base_version"] = "155.0.1"
                    product["upstream_compatibility"]["application_version"]["value"] = "155.0.1"

                def substituted(path: Path) -> dict:
                    if path == ROOT / "config/m15-08-native-update-contract.json":
                        return contract
                    if path == ROOT / "config/product-identity.json":
                        return product
                    return original_load(path)

                with patch.object(UPDATE, "load", side_effect=substituted):
                    with self.assertRaisesRegex(UPDATE.ContractError, "Firefox base mismatch"):
                        UPDATE.verify(ROOT)

    def test_mar_binding_rejects_previous_source_version(self) -> None:
        original_read_text = Path.read_text
        version_path = UPDATE.FIREFOX_SOURCE / "browser/config/version.txt"

        def stale_version(path: Path, *args: object, **kwargs: object) -> str:
            if path == version_path:
                return "155.0.1\n"
            return original_read_text(path, *args, **kwargs)

        with patch.object(Path, "read_text", stale_version):
            with self.assertRaisesRegex(UPDATE.ContractError, "MAR source version differs"):
                UPDATE.verify_mar_public_cert_binding(ROOT)

    def test_contract_cannot_enable_public_auto_update(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["trust"]["public_auto_update"] = "enabled"
        source = UPDATE.load

        def substituted(path: Path) -> dict:
            if path == ROOT / "config/m15-08-native-update-contract.json":
                return changed
            return source(path)

        with patch.object(UPDATE, "load", side_effect=substituted):
            with self.assertRaisesRegex(UPDATE.ContractError, "blocked-release gate"):
                UPDATE.verify(ROOT)

    def test_build_cannot_enable_updater_before_source_integration(self) -> None:
        original = Path.read_text

        def read_with_enabled_updater(path: Path, *args: object, **kwargs: object) -> str:
            result = original(path, *args, **kwargs)
            if path == ROOT / "overlay/build/goodbear/mozconfig":
                return result + "\nac_add_options --enable-updater\n"
            return result

        with patch.object(Path, "read_text", read_with_enabled_updater):
            with self.assertRaisesRegex(UPDATE.ContractError, "updater or unverified"):
                UPDATE.verify(ROOT)

    def test_eligible_offer_is_still_not_authorized(self) -> None:
        UPDATE.validate_offer_policy(self.offer, self.installed, self.contract)
        with self.assertRaisesRegex(UPDATE.ContractError, "public auto-update blocked"):
            UPDATE.authorize_public_update(self.offer, self.installed, self.contract)

    def test_adversarial_offers_rejected(self) -> None:
        cases = (
            ("product", "Firefox", "wrong product"),
            ("channel", "release", "wrong channel"),
            ("platform", "linux64", "platform mismatch"),
            ("mar_type", "partial", "partial"),
            ("app_version", "154.0", "Firefox-base mismatch"),
            ("mar_product_version", "154.0", "Firefox-base mismatch"),
            ("product_version", "1.0", "replay"),
            ("product_version", "1.0.0", "replay"),
            ("product_version", "0.9", "downgrade"),
            ("firefox_base_version", "154.0", "Firefox-base mismatch"),
            ("metadata_url", "http://github.com/owner/repo/releases/download/"
                             "goodbear-1.1-firefox155.0.2/update.xml", "pinned HTTPS"),
            ("mar_url", "https://github.com/owner/repo/releases/latest/download/update.mar",
             "pinned HTTPS"),
            ("mar_sha512", "0" * 64, "SHA-512"),
        )
        for field, value, error in cases:
            with self.subTest(field=field, value=value):
                offer = dict(self.offer, **{field: value})
                with self.assertRaisesRegex(UPDATE.ContractError, error):
                    UPDATE.validate_offer_policy(offer, self.installed, self.contract)

    def test_modified_mar_rejected_but_hash_is_not_signature(self) -> None:
        UPDATE.verify_mar_hash(b"test MAR bytes", self.offer["mar_sha512"])
        with self.assertRaisesRegex(UPDATE.ContractError, "modified MAR"):
            UPDATE.verify_mar_hash(b"modified MAR bytes", self.offer["mar_sha512"])
        with self.assertRaisesRegex(UPDATE.ContractError, "public auto-update blocked"):
            UPDATE.authorize_public_update(self.offer, self.installed, self.contract)

    def test_firefox_base_downgrade_rejected_even_with_new_product(self) -> None:
        offer = dict(self.offer, firefox_base_version="154.0", app_version="154.0",
                     mar_product_version="154.0", release_tag="goodbear-1.1-firefox154.0")
        offer["metadata_url"] = self.offer["metadata_url"].replace("155.0.2", "154.0")
        offer["mar_url"] = self.offer["mar_url"].replace("155.0.2", "154.0")
        with self.assertRaisesRegex(UPDATE.ContractError, "Firefox-base downgrade"):
            UPDATE.validate_offer_policy(offer, self.installed, self.contract)


if __name__ == "__main__":
    unittest.main()
