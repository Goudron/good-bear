#!/usr/bin/env python3
"""Fail-closed packaging guard for the pinned bundled RusSpell dictionary."""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "config/m15-06-ruspell-lock.json"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*\Z")

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def main() -> None:
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    assert set(lock) == {"schema_version", "task", "source", "dictionary", "update_procedure"}, (
        "unexpected or missing RusSpell lock field"
    )
    assert lock["schema_version"] == 1 and lock["task"] == "GB100-M15-06", (
        "invalid RusSpell lock metadata"
    )
    source = lock["source"]
    assert set(source) == {"repository", "commit", "version", "author", "license"}, (
        "unexpected or missing RusSpell source metadata"
    )
    assert isinstance(source["repository"], str) and source["repository"].startswith("local:"), (
        "RusSpell source repository must remain explicit"
    )
    assert isinstance(source["commit"], str) and COMMIT.fullmatch(source["commit"]), (
        "RusSpell source release must use an immutable commit"
    )
    assert isinstance(source["version"], str) and VERSION.fullmatch(source["version"]), (
        "RusSpell source release version is invalid"
    )
    assert isinstance(source["author"], str) and source["author"].strip(), (
        "RusSpell author attribution is missing"
    )
    assert source["license"] == "MPL-2.0", "RusSpell MPL-2.0 provenance is missing"
    assert isinstance(lock["update_procedure"], str) and "immutable RusSpell release" in lock["update_procedure"], (
        "RusSpell update procedure must require an immutable reviewed release"
    )
    item = lock["dictionary"]
    assert set(item) == {"locale", "extension_id", "primary", "files", "xpi_path", "xpi_sha256"}, (
        "unexpected or missing RusSpell dictionary field"
    )
    assert item["locale"] == "ru" and item["primary"] is True, "RusSpell must be the primary Russian dictionary"
    assert isinstance(item["extension_id"], str) and item["extension_id"].endswith("@valery-ledovskoy"), (
        "RusSpell extension identity is invalid"
    )
    assert set(item["files"]) == {"manifest.json", "LICENSE", "dictionaries/ru.aff", "dictionaries/ru.dic"}, (
        "RusSpell package must contain exactly the manifest, MPL notice and one ru.aff/ru.dic pair"
    )
    assert all(isinstance(value, str) and SHA256.fullmatch(value) for value in item["files"].values()), (
        "RusSpell member hash is invalid"
    )
    assert isinstance(item["xpi_sha256"], str) and SHA256.fullmatch(item["xpi_sha256"]), (
        "RusSpell XPI hash is invalid"
    )
    xpi = ROOT / item["xpi_path"]
    assert xpi.is_file(), f"missing bundled RusSpell XPI: {xpi}"
    assert digest(xpi.read_bytes()) == item["xpi_sha256"], "RusSpell XPI hash mismatch"
    with zipfile.ZipFile(xpi) as archive:
        names = set(archive.namelist())
        assert names == set(item["files"]), "unexpected or missing bundled dictionary member"
        for name, expected in item["files"].items():
            assert digest(archive.read(name)) == expected, f"RusSpell member hash mismatch: {name}"
        manifest = json.loads(archive.read("manifest.json"))
    assert manifest["version"] == source["version"], "unexpected RusSpell version"
    assert manifest["browser_specific_settings"]["gecko"]["id"] == item["extension_id"], "unexpected extension id"
    assert manifest["dictionaries"] == {"ru": "dictionaries/ru.dic"}, "second or non-primary Russian dictionary"
    print("M15-06 RusSpell packaging contract verified")

if __name__ == "__main__":
    main()
