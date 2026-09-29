#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools/product_identity.py"
SPEC = importlib.util.spec_from_file_location("product_identity", MODULE_PATH)
assert SPEC and SPEC.loader
IDENTITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IDENTITY)


class ProductIdentityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = json.loads(
            (ROOT / "config/product-identity.json").read_text(encoding="utf-8")
        )

    def test_repository_contract_is_consistent(self) -> None:
        IDENTITY.verify_contract(ROOT, self.identity)

    def test_rejects_declared_compatibility_without_the_native_ua_patch(self) -> None:
        original_read = Path.read_text
        target = ROOT / "patches" / IDENTITY.USER_AGENT_PATCH

        def without_native_binding(path, *args, **kwargs):
            value = original_read(path, *args, **kwargs)
            if path == target:
                return value.replace('+imply_option("MOZ_APP_UA_NAME", "Firefox")', "")
            return value

        with mock.patch.object(Path, "read_text", without_native_binding):
            with self.assertRaisesRegex(IDENTITY.IdentityError, "omits MOZ_APP_UA_NAME"):
                IDENTITY.verify_contract(ROOT, self.identity)

    def test_rejects_native_ua_patch_missing_from_series(self) -> None:
        original_read = Path.read_text

        def without_ua_patch(path, *args, **kwargs):
            value = original_read(path, *args, **kwargs)
            if path == ROOT / "patches/series":
                return value.replace(IDENTITY.USER_AGENT_PATCH, "")
            return value

        with mock.patch.object(Path, "read_text", without_ua_patch):
            with self.assertRaisesRegex(IDENTITY.IdentityError, "compatibility patch is not listed"):
                IDENTITY.verify_contract(ROOT, self.identity)

    def test_native_owner_rejects_missing_branded_or_conditional_ua_binding(self) -> None:
        baseline = json.loads((ROOT / "config/firefox-baseline.json").read_text())
        source = ROOT / "source/worktrees" / f"firefox-{baseline['version']}"
        original_read = Path.read_text
        target = source / "browser/moz.configure"
        actual = original_read(target)
        binding = 'imply_option("MOZ_APP_UA_NAME", "Firefox")'
        expected = actual if binding in actual else actual.replace(
            'imply_option("MOZ_APP_PROFILE", "goodbear")',
            'imply_option("MOZ_APP_PROFILE", "goodbear")\n' + binding,
        )
        alternatives = {
            "missing": expected.replace(binding, ""),
            "branded": expected.replace(binding, 'imply_option("MOZ_APP_UA_NAME", "GoodBear")'),
            "comment_only": expected.replace(binding, "# " + binding),
            "conditional": expected.replace(binding, 'if False:\n    ' + binding),
        }
        for label, text in {"preserved": expected, **alternatives}.items():
            def substituted(path, *args, **kwargs):
                return text if path == target else original_read(path, *args, **kwargs)

            with self.subTest(label=label), mock.patch.object(Path, "read_text", substituted):
                if label == "preserved":
                    IDENTITY.verify_user_agent_source(source)
                else:
                    with self.assertRaisesRegex(IDENTITY.IdentityError, "MOZ_APP_UA_NAME"):
                        IDENTITY.verify_user_agent_source(source)

    def test_mozconfig_is_deterministic_and_russian_only(self) -> None:
        generated = IDENTITY.render_mozconfig(self.identity)
        self.assertIn("MOZ_CO_LOCALES=ru\n", generated)
        self.assertNotIn("MOZ_CO_LOCALES=en-US", generated)
        self.assertIn("--disable-updater", generated)
        self.assertIn("--disable-crashreporter", generated)
        self.assertNotIn("mozilla-release", generated)

    def test_version_pair_is_explicit_and_matches_the_pinned_baseline(self) -> None:
        pair = self.identity["version_pair"]
        baseline = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))
        self.assertEqual(pair["good_bear_version"], "1.0")
        self.assertEqual(pair["firefox_base_version"], baseline["version"])
        self.assertEqual(
            pair["canonical_about_ru"],
            f"Good Bear 1.0 (Firefox {baseline['version']})",
        )

    def test_rejects_a_second_shipped_locale(self) -> None:
        self.identity["release"]["shipped_locales"].append("en-US")
        with self.assertRaisesRegex(IDENTITY.IdentityError, "only shipped locale"):
            IDENTITY.verify_contract(ROOT, self.identity)

    def test_matching_stale_package_versions_are_rejected(self) -> None:
        self.identity["version_pair"]["package_version"] = "1.0+firefox155.0.1"
        self.identity["build"]["package_version"] = "1.0+firefox155.0.1"
        with self.assertRaisesRegex(IDENTITY.IdentityError, "declared version pair"):
            IDENTITY.verify_contract(ROOT, self.identity)

    def test_owner_evidence_must_follow_the_pinned_source_revision(self) -> None:
        self.identity["upstream_owner_evidence"][0]["revision"] = (
            "fb95137a04eb8fe1196cb12f26b100c1e060295c"
        )
        with self.assertRaisesRegex(IDENTITY.IdentityError, "pinned Firefox source revision"):
            IDENTITY.verify_contract(ROOT, self.identity)

    def test_missing_owner_cannot_be_replaced_with_duplicate_evidence(self) -> None:
        self.identity["upstream_owner_evidence"][-1] = self.identity["upstream_owner_evidence"][0]
        with self.assertRaisesRegex(IDENTITY.IdentityError, "pinned Firefox source revision"):
            IDENTITY.verify_contract(ROOT, self.identity)

    def test_release_is_blocked_without_approved_original_artwork(self) -> None:
        with self.assertRaisesRegex(IDENTITY.IdentityError, "approved original Good Bear artwork"):
            IDENTITY.verify_contract(ROOT, self.identity, release=True)

    def test_technical_candidate_requires_buildable_placeholder_branding(self) -> None:
        branding = ROOT / "overlay" / self.identity["build"]["branding_directory"]
        for relative in ("moz.build", "locales/moz.build", "locales/jar.mn", "default16.png",
                         "default32.png", "default48.png", "default64.png", "default128.png"):
            self.assertTrue((branding / relative).is_file(), relative)

    def test_rejects_mozilla_service_endpoint(self) -> None:
        updater = self.identity["services"]["application_updater"]
        updater["endpoints"] = ["https://aus5.mozilla.org/update"]
        with self.assertRaisesRegex(IDENTITY.IdentityError, "must not inherit an endpoint"):
            IDENTITY.verify_contract(ROOT, self.identity)

    def test_about_dialog_names_the_creator_without_mozilla_project_links(self) -> None:
        branding = ROOT / "overlay" / self.identity["build"]["branding_directory"]
        strings = (branding / "locales" / "en-US" / "brand.ftl").read_text(encoding="utf-8")
        self.assertIn("Создатель и разработчик Good Bear — Валерий Ледовской.", strings)
        self.assertIn("Браузер создан на основе открытого исходного кода Mozilla Firefox.", strings)
        self.assertIn("Good Bear — независимый браузер, не связанный с Mozilla.", strings)

        about_patch = (ROOT / "patches" / "0002-good-bear-about-dialog-attribution.patch").read_text(
            encoding="utf-8"
        )
        self.assertIn('data-l10n-id="goodbear-about-description"', about_patch)
        self.assertIn('id="contributeDesc" hidden="true"', about_patch)
        self.assertNotIn(
            '+            <label is="text-link" href="https://www.mozilla.org/?utm_source=firefox-browser',
            about_patch,
        )


if __name__ == "__main__":
    unittest.main()
