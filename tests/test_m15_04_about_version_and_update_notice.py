from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))
FIREFOX = ROOT / "source" / "worktrees" / f"firefox-{BASELINE['version']}"
RU_ABOUT = ROOT / "source/l10n/firefox-l10n/ru/browser/browser/aboutDialog.ftl"


class AboutVersionAndUpdateNoticeTest(unittest.TestCase):
    def test_about_shows_the_good_bear_and_firefox_version_pair(self) -> None:
        dialog = (FIREFOX / "browser/base/content/aboutDialog.xhtml").read_text(encoding="utf-8")
        script = (FIREFOX / "browser/base/content/aboutDialog.js").read_text(encoding="utf-8")
        l10n = RU_ABOUT.read_text(encoding="utf-8")
        self.assertIn('id="goodbearUpdateInfo"', dialog)
        self.assertIn('data-l10n-id="goodbear-about-update-terminal"', dialog)
        self.assertIn('goodBearVersion: AppConstants.MOZ_APP_VERSION_DISPLAY', script)
        self.assertIn('firefoxVersion: Services.appinfo.version', script)
        self.assertIn('"goodbear-about-version"', script)
        self.assertIn('goodbear-about-version = Good Bear { $goodBearVersion } (Firefox { $firefoxVersion })', l10n)
        self.assertIn('goodbear-about-update-terminal =', l10n)


if __name__ == "__main__":
    unittest.main()
