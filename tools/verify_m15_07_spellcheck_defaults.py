#!/usr/bin/env python3
"""Fail-closed verifier for M15-07 fresh-profile spellcheck defaults."""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

from host_build_context import SOURCE


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = Path("config/m15-07-spellcheck-defaults.json")
RUSPELL_LOCK_PATH = Path("config/m15-06-ruspell-lock.json")
RUSPELL_EXTENSION_ID = "russian-spell-dictionary@valery-ledovskoy"
FIREFOX_SOURCE_PATH = SOURCE.relative_to(ROOT)
FIREFOX_PROFILE_PATH = FIREFOX_SOURCE_PATH / "browser/app/profile/firefox.js"


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(root: Path = ROOT) -> None:
    baseline = load(root / "config/firefox-baseline.json")
    source_version = (root / FIREFOX_SOURCE_PATH / "browser/config/version.txt").read_text(
        encoding="utf-8").strip()
    require(source_version == baseline.get("version"),
            "spellcheck source version differs from the pinned Firefox baseline")
    contract = load(root / CONTRACT_PATH)
    require(set(contract) == {"schema_version", "task", "fresh_profile", "languages", "user_choice", "network"},
            "unexpected or missing M15-07 contract field")
    require(contract.get("schema_version") == 1 and contract.get("task") == "GB100-M15-07",
            "invalid M15-07 spellcheck contract")
    require(contract.get("fresh_profile") == {
        "pref": "layout.spellcheckDefault",
        "value": 1,
        "meaning": "enable spelling for multiline editable controls",
    }, "fresh profiles must enable multiline spellcheck with layout.spellcheckDefault=1")
    require(contract.get("languages") == {
        "ru": {
            "source": "GB100-M15-06 bundled RusSpell",
            "extension_id": RUSPELL_EXTENSION_ID,
            "dictionary_path": "dictionaries/ru.dic",
        },
        "en-US": {
            "source": "Firefox built-in English spell checker",
            "policy": "retain; never replaced by the Russian primary dictionary",
        },
    }, "Russian RusSpell and built-in en-US dictionaries must remain the exact fresh-profile set")
    require(contract.get("network") == "No dictionary download is required for bundled Russian spelling.",
            "fresh-profile Russian spelling must not download a dictionary")
    require(contract.get("user_choice") ==
            "No user preference is locked; language selection remains content-language and user controlled.",
            "spellcheck language choice must not be locked")

    lock = load(root / RUSPELL_LOCK_PATH)
    dictionary = lock.get("dictionary", {})
    require(lock.get("schema_version") == 1 and lock.get("task") == "GB100-M15-06",
            "invalid M15-06 RusSpell lock")
    require(dictionary.get("locale") == "ru" and dictionary.get("primary") is True,
            "M15-06 must provide the primary Russian dictionary")
    require(dictionary.get("extension_id") == RUSPELL_EXTENSION_ID,
            "M15-06 RusSpell extension id differs from M15-07")
    require(dictionary.get("files", {}).get("dictionaries/ru.dic"),
            "M15-06 lock does not pin the Russian dictionary file")

    xpi_path = dictionary.get("xpi_path")
    require(isinstance(xpi_path, str) and xpi_path,
            "M15-06 lock does not declare a bundled RusSpell XPI path")
    xpi = root / xpi_path
    require(xpi.is_file(), f"missing bundled RusSpell XPI: {xpi}")
    require(sha256(xpi) == dictionary.get("xpi_sha256"), "bundled RusSpell XPI hash mismatch")
    with zipfile.ZipFile(xpi) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        require(manifest.get("browser_specific_settings", {}).get("gecko", {}).get("id") == RUSPELL_EXTENSION_ID,
                "bundled RusSpell XPI has an unexpected extension id")
        require(manifest.get("dictionaries") == {"ru": "dictionaries/ru.dic"},
                "bundled RusSpell XPI does not expose exactly the pinned Russian dictionary")

    profile = (root / FIREFOX_PROFILE_PATH).read_text(encoding="utf-8")
    default = 'pref("layout.spellcheckDefault", 1);'
    require(profile.count(default) == 1,
            "materialized Firefox profile must enable spellcheck exactly once for a fresh profile")
    require('lockPref("layout.spellcheckDefault"' not in profile and
            'pref("spellchecker.dictionary"' not in profile,
            "spellcheck language selection must remain user and content-language controlled")


def main() -> int:
    try:
        verify()
    except (ContractError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("M15-07 fresh-profile spellcheck defaults verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
