#!/usr/bin/env python3
"""Preflight and evidence guards, without fabricating screenshot evidence."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import run_m15_11_ru_shield_capture as CAPTURE


class CaptureGuardTest(unittest.TestCase):
    def test_missing_archive_blocks_before_browser_start(self):
        result = CAPTURE.prerequisites(ROOT / "missing-pinned-156-ru.tar.xz")
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(result["reasons"])
        self.assertIs(result["runtime_verified"], False)
        self.assertIs(result["visual_parity_proven"], False)
        self.assertIs(result["promotion_allowed"], False)

    def test_runtime_must_match_pinned_platform_and_russian_startup(self):
        CAPTURE.validate_identity({"locale": "ru", "platform_version": "156.0"}, "156.0")
        for locale, version in (("en-US", "156.0"), ("ru", "155.0.1"), ("ru-RU", "156.0")):
            with self.subTest(locale=locale, version=version), self.assertRaises(CAPTURE.ProbeError):
                CAPTURE.validate_identity({"locale": locale, "platform_version": version}, "156.0")

    def test_badge_is_never_evidence_without_native_trust_and_scope(self):
        valid = {"trust_domain": 2, "context_id": 4, "private_id": 0,
                 "badge": "RU", "badge_visible": True,
                 "describedby": "trust-goodbear-russian-pki-description",
                 "viewport": [1920, 1080], "device_pixel_ratio": 1.25}
        CAPTURE.validate_ru_state(valid, scale=1.25)
        for key, value in (("trust_domain", 1), ("trust_domain", 0), ("context_id", 0),
                           ("private_id", 1), ("badge_visible", False), ("describedby", None),
                           ("viewport", [1280, 720]), ("device_pixel_ratio", 1)):
            with self.subTest(key=key, value=value), self.assertRaises(CAPTURE.ProbeError):
                CAPTURE.validate_ru_state(valid | {key: value}, scale=1.25)


if __name__ == "__main__":
    unittest.main()
