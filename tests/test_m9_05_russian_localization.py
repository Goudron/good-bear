#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from host_build_context import SOURCE as FIREFOX, L10N_BASE
EN_BROWSER = FIREFOX / "browser/locales/en-US/browser/browser.ftl"
EN_PREFERENCES = FIREFOX / "browser/locales/en-US/browser/preferences/goodBearRussianPKI.ftl"
RU_BROWSER = L10N_BASE / "ru/browser/browser/browser.ftl"
RU_PREFERENCES = L10N_BASE / "ru/browser/browser/preferences/goodBearRussianPKI.ftl"


def messages(path: Path) -> dict[str, str]:
    source = path.read_text(encoding="utf-8")
    positions = list(re.finditer(r"(?m)^([a-z][a-z0-9-]+)\s*=", source))
    result = {}
    for index, match in enumerate(positions):
        end = positions[index + 1].start() if index + 1 < len(positions) else len(source)
        result[match.group(1)] = source[match.start() : end]
    return result


class M905RussianLocalizationTest(unittest.TestCase):
    def test_every_goodbear_fluent_message_has_a_russian_value(self) -> None:
        for source_path, russian_path in ((EN_BROWSER, RU_BROWSER), (EN_PREFERENCES, RU_PREFERENCES)):
            source_messages = messages(source_path)
            russian_messages = messages(russian_path)
            identifiers = [
                key
                for key in source_messages
                if key.startswith(("goodbear-", "identity-goodbear-", "urlbar-goodbear-"))
            ]
            self.assertTrue(identifiers, source_path)
            self.assertTrue(set(identifiers) <= set(russian_messages), russian_path)
            for identifier in identifiers:
                source_value = re.sub(
                    r"(?m)^\s*#.*$", "", source_messages[identifier]
                )
                russian_value = re.sub(
                    r"(?m)^\s*#.*$", "", russian_messages[identifier]
                )
                self.assertEqual(
                    set(re.findall(r"\$([A-Za-z][A-Za-z0-9_]*)", source_value)),
                    set(re.findall(r"\$([A-Za-z][A-Za-z0-9_]*)", russian_value)),
                    identifier,
                )

        # en-US is the required internal source/fallback; only ru is shipped.
        preferences = messages(RU_PREFERENCES)
        expected = {
            "goodbear-russian-pki-settings-header",
            "goodbear-russian-pki-settings-enable",
            "goodbear-russian-pki-settings-enable-failed",
            "goodbear-russian-pki-settings-enabled-state",
            "goodbear-russian-pki-settings-disabled-state",
            "goodbear-russian-pki-settings-sites-header",
            "goodbear-russian-pki-settings-sites-description",
            "goodbear-russian-pki-settings-sites-list",
            "goodbear-russian-pki-settings-sites-empty",
            "goodbear-russian-pki-settings-reset-origin",
            "goodbear-russian-pki-settings-reset-origin-confirmation",
            "goodbear-russian-pki-settings-reset-all",
            "goodbear-russian-pki-settings-reset-all-confirmation",
            "goodbear-russian-pki-settings-reset-all-confirm",
            "goodbear-russian-pki-settings-reset-failed",
            "goodbear-russian-pki-settings-credentials-header",
            "goodbear-russian-pki-settings-credentials-description",
        }
        self.assertEqual(set(preferences), expected)
        self.assertEqual(
            set(re.findall(r"\$([A-Za-z][A-Za-z0-9_]*)", preferences["goodbear-russian-pki-settings-reset-origin"])),
            {"origin"},
        )

    def test_visible_container_label_uses_fluent_not_a_javascript_literal(self) -> None:
        owner = (FIREFOX / "browser/base/content/browser-siteIdentity.js").read_text(
            encoding="utf-8"
        )
        self.assertIn('"trust-goodbear-russian-pki-label"', owner)
        self.assertIn('"identity-goodbear-russian-pki-label"', owner)
        self.assertIn("document.l10n.setAttributes", owner)
        manager = (FIREFOX / "browser/components/GoodBearRussianPKIContainer.sys.mjs").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('const CONTAINER_NAME =', manager)
        self.assertIn('new Localization(["browser/browser.ftl"], true)', manager)
        self.assertIn('"urlbar-goodbear-russian-pki-container-label"', manager)
        marker = (FIREFOX / "browser/components/tabbrowser/Tabbrowser.sys.mjs").read_text(
            encoding="utf-8"
        )
        self.assertIn('"urlbar-goodbear-russian-pki-container-marker"', marker)
        self.assertIn('hbox.removeAttribute("aria-label")', marker)

    def test_interstitial_and_prompt_have_no_hard_coded_user_text(self) -> None:
        child = (FIREFOX / "browser/actors/GoodBearRussianPKICertificateErrorChild.sys.mjs").read_text(
            encoding="utf-8"
        )
        parent = (FIREFOX / "browser/actors/GoodBearRussianPKICertificateErrorParent.sys.mjs").read_text(
            encoding="utf-8"
        )
        for literal in (
            "Требуется изолированный контейнер",
            "Открыть изолированно",
            "Просмотреть сертификат",
            "Good Bear — Российская PKI",
        ):
            self.assertNotIn(literal, child)
            self.assertNotIn(literal, parent)
        self.assertIn("securityInfo?.goodBearRussianPKIRequired", child)
        self.assertIn("openAddressOnlyAfterRussianPKICertificateError", parent)

    def test_live_interstitial_catalogue_matches_consumed_ids_without_superseded_prompts(self) -> None:
        interstitial = (FIREFOX / "browser/components/GoodBearRussianPKIInterstitial.sys.mjs").read_text(
            encoding="utf-8"
        )
        live = set(re.findall(r'"(goodbear-russian-pki-interstitial-[a-z-]+)"', interstitial))
        self.assertEqual(len(live), 9)
        for path in (EN_BROWSER, RU_BROWSER):
            catalogue = messages(path)
            self.assertEqual({identifier for identifier in catalogue
                              if identifier.startswith("goodbear-russian-pki-interstitial-")}, live)
            self.assertFalse(any(identifier.startswith("goodbear-russian-pki-prompt-")
                                 for identifier in catalogue))

    def test_origin_variable_is_supplied_by_the_settings_ui(self) -> None:
        settings = RU_PREFERENCES.read_text(encoding="utf-8")
        manager = (FIREFOX / "browser/components/GoodBearRussianPKIContainer.sys.mjs").read_text(
            encoding="utf-8"
        )
        self.assertIn("goodbear-russian-pki-settings-reset-origin = Удалить { $origin }", settings)
        self.assertIn("async resetAssignment(origin)", manager)

    def test_indicator_has_non_color_accessible_affordances_for_all_themes_and_zoom(self) -> None:
        css = (FIREFOX / "browser/themes/shared/identity-block/identity-block.css").read_text(
            encoding="utf-8"
        )
        test = (
            FIREFOX
            / "browser/base/content/browser-siteIdentity.js"
        ).read_text(encoding="utf-8")
        self.assertIn("#trust-goodbear-russian-pki-label", css)
        self.assertIn("font-weight: 600", css)
        self.assertIn('"trust-goodbear-russian-pki-label"', test)
        self.assertIn('"identity-goodbear-russian-pki-label"', test)
        self.assertNotIn("width:", css.split("#trust-goodbear-russian-pki-label", 1)[1].split("}", 1)[0])

    def test_russian_pki_indicator_uses_the_compact_ru_label(self) -> None:
        russian = messages(RU_BROWSER)
        self.assertIn("identity-goodbear-russian-pki-label", russian)
        self.assertIn("= RU", russian["identity-goodbear-russian-pki-label"])
        self.assertNotIn("RU PKI", russian["identity-goodbear-russian-pki-label"])

    def test_russian_repack_is_the_only_shipped_artifact_path(self) -> None:
        build = (ROOT / "tools/build_host_russian.py").read_text(encoding="utf-8")
        context = (ROOT / "tools/host_build_context.py").read_text(encoding="utf-8")
        self.assertIn('("build", "installers-ru")', build)
        self.assertIn('"sole shipped locale: ru"', context)
        self.assertNotIn("installers-en-US", build)


if __name__ == "__main__":
    unittest.main()
