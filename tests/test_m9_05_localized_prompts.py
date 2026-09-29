"""Execute current blocking consent methods; retain the M9-05 coverage contract."""

from pathlib import Path
import re
import unittest

from test_m9_03_interstitial import (
    CHOICES, LOCALIZATION_FAILURES, GLUE, MODULE, run_controller,
)


class LocalizedPromptTest(unittest.TestCase):
    def test_consent_text_has_no_russian_javascript_literal(self):
        source = GLUE.read_text()
        method = source.split("\n  _promptAddressOnlyOpen(", 1)[1].split(
            "\n  _openAddressOnlyInContainer(", 1)[0]
        self.assertIsNone(re.search(r"[А-Яа-яЁё]", method))
        self.assertIsNone(re.search(r"[А-Яа-яЁё]", MODULE.read_text()))

    def test_all_choices_use_fluent_and_preserve_navigation_result(self):
        run_controller(CHOICES)

    def test_missing_localization_cannot_authorize_navigation(self):
        run_controller(LOCALIZATION_FAILURES)


if __name__ == "__main__":
    unittest.main()
