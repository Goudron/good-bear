#!/usr/bin/env python3
"""Adversarial fixtures for the pinned Fluent AST audit, without browser claims."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_m15_11_fluent_audit as AUDIT


class FluentAuditTest(unittest.TestCase):
    def entry(self, text: str) -> dict:
        return AUDIT.catalogue(text, "synthetic-test.ftl")["test-message"]

    def test_malformed_syntax_duplicate_ids_and_duplicate_attributes_fail_closed(self) -> None:
        for text in (
            "test-message = { $unclosed\n",
            "test-message = One\ntest-message = Two\n",
            "test-message = Text\n    .title = One\n    .title = Two\n",
        ):
            with self.subTest(text=text), self.assertRaises(AUDIT.FluentAuditError):
                AUDIT.catalogue(text, "synthetic-test.ftl")

    def test_translation_preserves_value_attributes_variables_and_named_slots(self) -> None:
        english = self.entry('test-message = Remove <label data-l10n-name="origin">{ $origin }</label>\n    .title = Remove site\n')
        russian = self.entry('test-message = Удалить <label data-l10n-name="origin">{ $origin }</label>\n    .title = Удалить сайт\n')
        self.assertEqual(AUDIT.message_issues(english, russian), [])
        for translated, fragment in (
            ('test-message = Удалить { $origin }\n', "value/attribute"),
            ('test-message = Удалить <label data-l10n-name="origin">{ $host }</label>\n    .title = Удалить сайт\n', "references changed"),
            ('test-message = Удалить { $origin }\n    .title = Удалить сайт\n', "markup slots changed"),
        ):
            with self.subTest(fragment=fragment):
                self.assertTrue(any(fragment in issue for issue in AUDIT.message_issues(english, self.entry(translated))))

    def test_russian_plural_expansion_and_many_default_are_valid(self) -> None:
        english = self.entry('test-message = { $count ->\n    [0] No trackers\n    [one] One tracker\n   *[other] { $count } trackers\n    }\n')
        russian_text = 'test-message = { $count ->\n    [0] Нет трекеров\n    [one] { $count } трекер\n    [few] { $count } трекера\n   *[many] { $count } трекеров\n    }\n'
        self.assertEqual(AUDIT.message_issues(english, self.entry(russian_text)), [])
        for mutation in (
            russian_text.replace('    [0] Нет трекеров\n', ''),
            russian_text.replace('$count', '$different'),
        ):
            self.assertTrue(AUDIT.message_issues(english, self.entry(mutation)))

    def test_enum_keys_defaults_and_nested_selectors_cannot_drift(self) -> None:
        original = self.entry('test-message = { $state ->\n    [enabled] Enabled\n   *[disabled] Disabled\n    }\n')
        changed = self.entry('test-message = { $state ->\n   *[enabled] Включено\n    [disabled] Выключено\n    }\n')
        self.assertTrue(any('selector' in issue for issue in AUDIT.message_issues(original, changed)))
        changed = self.entry('test-message = { $state ->\n    [enabled] Включено\n   *[unknown] Неизвестно\n    }\n')
        self.assertTrue(AUDIT.message_issues(original, changed))

    def test_accesskeys_are_a_single_visible_character_of_the_label(self) -> None:
        self.assertEqual(AUDIT.accesskey_issues(self.entry('test-message =\n    .label = Открыть\n    .accesskey = О\n')), [])
        for key in ('OO', 'Z', '{ $key }'):
            with self.subTest(key=key):
                self.assertTrue(AUDIT.accesskey_issues(self.entry(f'test-message =\n    .label = Открыть\n    .accesskey = {key}\n')))

    def test_term_message_and_function_references_cannot_be_replaced(self) -> None:
        english = self.entry('test-message = { -brand-name } { another-message.title } { NUMBER($count) }\n')
        russian = self.entry('test-message = { -other-brand } { other-message.title } { DATETIME($count) }\n')
        self.assertTrue(any('references changed' in issue for issue in AUDIT.message_issues(english, russian)))
        english = self.entry('test-message = { NUMBER($count, maximumFractionDigits: 1) }\n')
        russian = self.entry('test-message = { NUMBER($count, maximumFractionDigits: 4) }\n')
        self.assertTrue(any('function arguments changed' in issue for issue in AUDIT.message_issues(english, russian)))

    def mutated_audit(self, target: Path, change) -> dict:
        original_read = Path.read_text

        def read(path, *args, **kwargs):
            text = original_read(path, *args, **kwargs)
            return change(text) if path == target else text

        with patch.object(Path, 'read_text', read):
            return AUDIT.audit()

    def test_missing_russian_message_and_attribute_are_fallback_risks(self) -> None:
        target = AUDIT.L10N_BASE / 'ru/browser/browser/browser.ftl'
        for text in (
            'identity-goodbear-russian-pki-label = RU\n    .tooltiptext = Сертификат проверен через Российскую PKI\n',
            '    .tooltiptext = Сертификат проверен через Российскую PKI\n',
        ):
            with self.subTest(text=text):
                report = self.mutated_audit(target, lambda value: value.replace(text, ''))
                self.assertEqual(report['status'], 'blocked')
                self.assertTrue(any(item['id'] == 'identity-goodbear-russian-pki-label'
                                    for item in report['fallback_findings']))

    def test_registered_message_cannot_reference_an_unregistered_brand_resource(self) -> None:
        report = self.mutated_audit(AUDIT.SOURCE / 'browser/base/content/browser.xhtml',
                                   lambda text: text.replace('<link rel="localization" href="branding/brand.ftl"/>', ''))
        self.assertTrue(any(item.get('reference') == '-brand-product-name' and
                            'not registered' in item['issue'] for item in report['binding_findings']))

    def test_repository_audit_keeps_bindings_and_fallback_risks_separate_from_runtime(self) -> None:
        report = AUDIT.audit()
        self.assertGreater(report['checked_message_count'], 100)
        self.assertGreater(report['bound_message_count'], 50)
        self.assertEqual(report['structural_findings'], [])
        self.assertIsInstance(report['fallback_findings'], list)
        self.assertIsInstance(report['binding_findings'], list)
        self.assertIs(report['runtime_verified'], False)
        self.assertIsNone(report['visible_english_observed'])
        self.assertIs(report['visual_parity_proven'], False)
        self.assertEqual(report['status'], 'blocked' if any(report[key] for key in (
            'structural_findings', 'fallback_findings', 'binding_findings')) else 'passed')

    def test_interstitial_bundle_and_preferences_registration_are_independent(self) -> None:
        report = self.mutated_audit(
            AUDIT.SOURCE / 'browser/components/GoodBearRussianPKIInterstitial.sys.mjs',
            lambda text: text.replace('["browser/browser.ftl"]', '[]'))
        self.assertTrue(any(item.get('id') == 'goodbear-russian-pki-interstitial-title'
                            and 'absent' in item['issue'] for item in report['binding_findings']))
        report = self.mutated_audit(
            AUDIT.SOURCE / 'browser/components/preferences/preferences.xhtml',
            lambda text: text.replace('<link rel="localization" href="browser/preferences/goodBearRussianPKI.ftl"/>', ''))
        self.assertTrue(any(item.get('id') == 'goodbear-russian-pki-settings-enable'
                            and 'absent' in item['issue'] for item in report['binding_findings']))

    def test_interstitial_document_resource_and_model_are_checked_separately(self) -> None:
        report = self.mutated_audit(
            AUDIT.SOURCE / 'browser/base/content/goodbearRussianPKIInterstitial.xhtml',
            lambda text: text.replace('<link rel="localization" href="browser/browser.ftl" />', ''))
        self.assertTrue(any('document resource' in item['issue'] for item in report['binding_findings']))
        report = self.mutated_audit(
            AUDIT.SOURCE / 'browser/components/GoodBearRussianPKIInterstitial.sys.mjs',
            lambda text: text.replace('"goodbear-russian-pki-interstitial-title",', '"Непереведённый заголовок",'))
        self.assertTrue(any('literals bypass Fluent' in item['issue'] for item in report['binding_findings']))
        self.assertTrue(any(item.get('id') == 'goodbear-russian-pki-interstitial-title'
                            and 'no binding' in item['issue'] for item in report['binding_findings']))

    def test_consumed_array_id_missing_from_both_catalogues_still_fails(self) -> None:
        import re
        original_read = Path.read_text
        targets = {AUDIT.SOURCE / 'browser/locales/en-US/browser/browser.ftl',
                   AUDIT.L10N_BASE / 'ru/browser/browser/browser.ftl'}

        def read(path, *args, **kwargs):
            text = original_read(path, *args, **kwargs)
            if path in targets:
                return re.sub(r'^goodbear-russian-pki-interstitial-title =[^\n]*\n', '', text, flags=re.M)
            return text

        with patch.object(Path, 'read_text', read):
            report = AUDIT.audit()
        self.assertEqual(report['status'], 'blocked')
        self.assertTrue(any(item.get('id') == 'goodbear-russian-pki-interstitial-title'
                            for item in report['fallback_findings']))

    def test_container_name_owns_an_independent_registered_bundle(self) -> None:
        report = self.mutated_audit(
            AUDIT.SOURCE / 'browser/components/GoodBearRussianPKIContainer.sys.mjs',
            lambda text: text.replace('new Localization(["browser/browser.ftl"], true)',
                                      'new Localization([], true)'))
        self.assertTrue(any(item.get('id') == 'urlbar-goodbear-russian-pki-container-label'
                            and 'absent' in item['issue'] for item in report['binding_findings']))

    def test_shared_security_details_and_marker_are_actual_localized_consumers(self) -> None:
        report = AUDIT.audit()
        residual = {item.get('id') for item in report['binding_findings']}
        for identifier in (
            'identity-goodbear-russian-pki-leaf-label',
            'identity-goodbear-russian-pki-root-label',
            'identity-goodbear-russian-pki-root-fingerprint-label',
            'identity-goodbear-russian-pki-scoped-anchor-explanation',
            'identity-goodbear-russian-pki-view-certificate',
            'urlbar-goodbear-russian-pki-container-label',
            'urlbar-goodbear-russian-pki-container-marker',
        ):
            self.assertNotIn(identifier, residual)
        owner = 'browser/components/controlcenter/content/securityInformation.inc.xhtml'
        self.assertIn(owner, report['owner_sha256'])


if __name__ == '__main__':
    unittest.main()
