#!/usr/bin/env python3
"""Verify that a shipped Good Bear archive contains Russian resources only."""

from __future__ import annotations

import argparse
from pathlib import Path
import tarfile
import zipfile

from project_temp import temporary_directory


class ArchiveError(RuntimeError):
    pass


REQUIRED_BROWSER_RUSSIAN_RESOURCES = (
    "localization/ru/browser/appmenu.ftl",
    "localization/ru/browser/browser.ftl",
    "localization/ru/browser/protectionsPanel.ftl",
    "localization/ru/browser/sitePermissions.ftl",
)


def archive_entries(omni: Path) -> set[str]:
    with zipfile.ZipFile(omni) as bundle:
        return set(bundle.namelist())


def verify(archive: Path) -> None:
    if not archive.is_file():
        raise ArchiveError(f"archive does not exist: {archive}")
    with temporary_directory(prefix="good-bear-russian-archive-") as temporary:
        root = Path(temporary)
        with tarfile.open(archive, "r:xz") as bundle:
            bundle.extractall(root, filter="data")
        application = root / "goodbear"
        global_omni = application / "omni.ja"
        browser_omni = application / "browser" / "omni.ja"
        for omni in (global_omni, browser_omni):
            entries = archive_entries(omni)
            if any("/localization/en-US/" in f"/{entry}" for entry in entries):
                raise ArchiveError(f"en-US localization leaked into {omni.name}")
            if not any("/localization/ru/" in f"/{entry}" for entry in entries):
                raise ArchiveError(f"Russian localization missing from {omni.name}")
        with zipfile.ZipFile(browser_omni) as bundle:
            for resource in REQUIRED_BROWSER_RUSSIAN_RESOURCES:
                try:
                    contents = bundle.read(resource)
                except KeyError as exc:
                    raise ArchiveError(
                        f"required Russian Fluent resource missing from browser omni: {resource}"
                    ) from exc
                if not contents:
                    raise ArchiveError(
                        f"required Russian Fluent resource is empty in browser omni: {resource}"
                    )
        with zipfile.ZipFile(global_omni) as bundle:
            multilocale = bundle.read("res/multilocale.txt").decode("utf-8")
        if multilocale != "ru\n":
            raise ArchiveError(f"expected multilocale.txt to be ru, got {multilocale!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    try:
        verify(args.archive)
    except (ArchiveError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}")
        return 1
    print("Russian-only release archive verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
