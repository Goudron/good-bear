#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Verify the M10-04 public Good Bear identity without erasing provenance."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_build_context import FIREFOX_WORKTREE_NAME, SOURCE  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PATCH_NAME = "0016-good-bear-public-product-rebranding.patch"
PATCH_TARGETS = {
    "python/mozbuild/mozbuild/repackaging/utils.py",
    "browser/installer/linux/app/debian/control.in",
    "browser/installer/linux/app/debian/changelog.in",
    "browser/installer/linux/app/debian/distribution.ini",
    "browser/installer/linux/app/debian/install.in",
    "browser/installer/linux/app/debian/links.in",
    "browser/installer/linux/app/debian/manpage.1.in",
    "browser/installer/linux/app/debian/manpages.in",
    "browser/installer/linux/app/debian/postinst.in",
    "browser/installer/linux/app/debian/prerm.in",
}
REQUIRED_PATCH_ADDITIONS = {
    'pkg_name = f"goodbear-browser{package_name_suffix}"',
    'public_executable_name = "goodbear"',
    'desktop_file_id = "com.ledovskoy.goodbear.desktop"',
    '"APP_BINARY_NAME": app_binary_name,',
    '"PUBLIC_EXECUTABLE_NAME": public_executable_name,',
    '"DESKTOP_FILE_ID": desktop_file_id,',
    "Maintainer: Good Bear Project <valery@ledovskoy.com>",
    "id=goodbear-ubuntu",
    "about=Good Bear Ubuntu Package",
    "${APP_BINARY_NAME}/* ${PKG_INSTALL_PATH}",
    "debian/${DESKTOP_FILE_ID} usr/share/applications",
    "${PKG_INSTALL_PATH}/${APP_BINARY_NAME} usr/bin/${PUBLIC_EXECUTABLE_NAME}",
    '.SS "Browser options"',
    "Good Bear is an independent browser based on Mozilla Firefox open-source code.",
    "Good Bear is not affiliated with or endorsed by Mozilla.",
}
FORBIDDEN_PATCH_ADDITIONS = {
    "Maintainer: Mozilla <release@mozilla.com>",
    "id=mozilla-deb",
    "about=Mozilla Firefox Debian Package",
    "firefox/* ${PKG_INSTALL_PATH}",
    "${PKG_INSTALL_PATH}/firefox usr/bin/${PKG_NAME}",
    '.SS "Mozilla options"',
    "To report a bug, please visit \\fIhttp://bugzilla.mozilla.org/\\fR",
}
LEGAL_TARGET_PATTERNS = (
    re.compile(r"(^|/)(license|licenses|notice|notices)([./]|$)", re.IGNORECASE),
    re.compile(r"(^|/)third[_-]?party([./]|$)", re.IGNORECASE),
)
ACTIVE_SOURCE_REQUIREMENTS = {
    "python/mozbuild/mozbuild/repackaging/utils.py": {
        'pkg_name = f"goodbear-browser{package_name_suffix}"',
        'public_executable_name = "goodbear"',
        'desktop_file_id = "com.ledovskoy.goodbear.desktop"',
        'desktop_entry_file_filename = build_variables["DESKTOP_FILE_ID"]',
    },
    "browser/installer/linux/app/debian/control.in": {
        "Maintainer: Good Bear Project <valery@ledovskoy.com>",
    },
    "browser/installer/linux/app/debian/changelog.in": {
        " -- Good Bear Project <valery@ledovskoy.com>  ${CHANGELOG_DATE}",
    },
    "browser/installer/linux/app/debian/distribution.ini": {
        "id=goodbear-ubuntu",
        "about=Good Bear Ubuntu Package",
    },
    "browser/installer/linux/app/debian/install.in": {
        "${APP_BINARY_NAME}/* ${PKG_INSTALL_PATH}",
        "debian/${DESKTOP_FILE_ID} usr/share/applications",
    },
    "browser/installer/linux/app/debian/links.in": {
        "${PKG_INSTALL_PATH}/${APP_BINARY_NAME} usr/bin/${PUBLIC_EXECUTABLE_NAME}",
    },
    "browser/installer/linux/app/debian/manpage.1.in": {
        '.SS "Browser options"',
        "Good Bear is an independent browser based on Mozilla Firefox open-source code.",
        "Good Bear is not affiliated with or endorsed by Mozilla.",
    },
    "browser/installer/linux/app/debian/manpages.in": {
        "debian/${PUBLIC_EXECUTABLE_NAME}.1",
    },
    "browser/installer/linux/app/debian/postinst.in": {
        "gnome-www-browser /usr/bin/${PUBLIC_EXECUTABLE_NAME} 100 \\",
        "x-www-browser /usr/bin/${PUBLIC_EXECUTABLE_NAME} 100 \\",
    },
    "browser/installer/linux/app/debian/prerm.in": {
        "update-alternatives --remove x-www-browser /usr/bin/${PUBLIC_EXECUTABLE_NAME}",
        "update-alternatives --remove gnome-www-browser /usr/bin/${PUBLIC_EXECUTABLE_NAME}",
    },
}
ACTIVE_SOURCE_FORBIDDEN = {
    "browser/installer/linux/app/debian/control.in": {
        "Maintainer: Mozilla <release@mozilla.com>",
    },
    "browser/installer/linux/app/debian/distribution.ini": {
        "id=mozilla-deb",
        "about=Mozilla Firefox Debian Package",
    },
    "browser/installer/linux/app/debian/install.in": {
        "firefox/* ${PKG_INSTALL_PATH}",
    },
    "browser/installer/linux/app/debian/links.in": {
        "${PKG_INSTALL_PATH}/firefox usr/bin/${PKG_NAME}",
    },
    "browser/installer/linux/app/debian/manpage.1.in": {
        '.SS "Mozilla options"',
        "To report a bug, please visit \\fIhttp://bugzilla.mozilla.org/\\fR",
    },
}


class RebrandingError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RebrandingError(message)


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RebrandingError(f"cannot load {path}: {exc}") from exc
    require(isinstance(value, dict), f"{path} must contain a JSON object")
    return value


def series_entries(root: Path) -> list[str]:
    lines = (root / "patches" / "series").read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def added_lines(patch_text: str) -> set[str]:
    return {
        line[1:].strip()
        for line in patch_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    }


def patch_targets(patch_text: str) -> set[str]:
    return {
        line.removeprefix("+++ b/")
        for line in patch_text.splitlines()
        if line.startswith("+++ b/")
    }


def validate(
    root: Path = ROOT,
    *,
    identity: dict | None = None,
    patch_text: str | None = None,
) -> None:
    identity = identity or load_json(root / "config" / "product-identity.json")
    release = identity.get("release", {})
    product = identity.get("product", {})
    compatibility = identity.get("upstream_compatibility", {})

    require(product.get("name") == "Good Bear", "application display identity must be Good Bear")
    expected_release = {
        "platform": "ubuntu",
        "architecture": "amd64",
        "locale": "ru",
        "shipped_locales": ["ru"],
        "package_name": "goodbear-browser",
        "executable_name": "goodbear",
        "desktop_file_id": "com.ledovskoy.goodbear.desktop",
        "desktop_display_name": "Good Bear",
        "profile_namespace": "goodbear",
    }
    for key, expected in expected_release.items():
        require(release.get(key) == expected, f"release.{key} must be {expected!r}")

    app_id = compatibility.get("application_id", {})
    ua_product = compatibility.get("user_agent_product", {})
    app_version = compatibility.get("application_version", {})
    require(app_id.get("value") == "{ec8030f7-c20a-464f-9b0e-13a3a9e97384}" and
            app_id.get("disposition") == "preserve",
            "the Firefox application ID must remain an explicit compatibility identifier")
    require(ua_product.get("value") == "Firefox" and ua_product.get("disposition") == "preserve",
            "the Firefox UA token must remain an explicit web-compatibility identifier")
    require(app_version.get("disposition") == "preserve",
            "the Gecko application version must remain an explicit compatibility identifier")

    entries = series_entries(root)
    require(entries.count(PATCH_NAME) == 1, f"{PATCH_NAME} must occur exactly once in patches/series")
    require(entries.index(PATCH_NAME) > entries.index("0015-good-bear-strict-russian-release-locale.patch"),
            "public rebranding patch must retain the earlier strict Russian-locale patch")

    if patch_text is None:
        patch_text = (root / "patches" / PATCH_NAME).read_text(encoding="utf-8")
    targets = patch_targets(patch_text)
    require(targets == PATCH_TARGETS,
            "public rebranding patch target set changed: " +
            ", ".join(sorted(targets.symmetric_difference(PATCH_TARGETS))))
    require(not any(pattern.search(target) for target in targets for pattern in LEGAL_TARGET_PATTERNS),
            "public rebranding patch must not rewrite license, notice, or third-party files")

    additions = added_lines(patch_text)
    forbidden = sorted(FORBIDDEN_PATCH_ADDITIONS & additions)
    require(not forbidden, "upstream product identity was added to a public surface: " +
            ", ".join(forbidden))
    missing = sorted(REQUIRED_PATCH_ADDITIONS - additions)
    require(not missing, "public rebranding patch is missing additions: " + ", ".join(missing))

    branding = root / "overlay" / "browser" / "branding" / "goodbear" / "locales" / "en-US"
    ftl = (branding / "brand.ftl").read_text(encoding="utf-8")
    properties = (branding / "brand.properties").read_text(encoding="utf-8")
    for key in ("-brand-shorter-name", "-brand-short-name", "-brand-shortcut-name",
                "-brand-full-name", "-brand-product-name"):
        require(f"{key} = Good Bear" in ftl, f"{key} must expose Good Bear")
    for key in ("brandShorterName", "brandShortName", "brandFullName"):
        require(f"{key}=Good Bear" in properties, f"{key} must expose Good Bear")
    require("Mozilla Firefox" in ftl and "не связанный с Mozilla" in ftl,
            "descriptive upstream attribution and Mozilla non-affiliation must remain")


def check_patch_application(root: Path = ROOT) -> None:
    source = root / "source" / "pristine" / FIREFOX_WORKTREE_NAME
    marker = load_json(source / ".good-bear-pristine.json")
    baseline = load_json(root / "config" / "firefox-baseline.json")
    require(marker.get("version") == baseline.get("version"),
            "pinned pristine source version does not match the Firefox baseline")
    for algorithm in ("sha256", "sha512"):
        require(marker.get(f"source_{algorithm}") == baseline.get("source", {}).get(algorithm),
                f"pinned pristine source {algorithm} does not match the Firefox baseline")
    patch = root / "patches" / PATCH_NAME
    environment = os.environ.copy()
    environment["GIT_CEILING_DIRECTORIES"] = str(source.parent.resolve())
    result = subprocess.run(
        ["git", "apply", "--no-index", "--check", "--whitespace=error-all", str(patch)],
        cwd=source,
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )
    require(result.returncode == 0, "public rebranding patch does not apply to pristine source: " +
            (result.stderr.strip() or result.stdout.strip()))


def active_source_texts(root: Path = ROOT) -> dict[str, str]:
    source = SOURCE
    texts = {}
    for relative in ACTIVE_SOURCE_REQUIREMENTS:
        try:
            texts[relative] = (source / relative).read_text(encoding="utf-8")
        except OSError as exc:
            raise RebrandingError(f"cannot read active M10-04 owner {relative}: {exc}") from exc
    return texts


def check_active_source(
    root: Path = ROOT,
    *,
    texts: dict[str, str] | None = None,
) -> None:
    if texts is None:
        texts = active_source_texts(root)
    for relative, forbidden_fragments in ACTIVE_SOURCE_FORBIDDEN.items():
        text = texts.get(relative, "")
        present = sorted(fragment for fragment in forbidden_fragments if fragment in text)
        require(not present, f"active source retains prohibited public identity in {relative}: " +
                ", ".join(present))
    for relative, required_fragments in ACTIVE_SOURCE_REQUIREMENTS.items():
        text = texts.get(relative, "")
        missing = sorted(fragment for fragment in required_fragments if fragment not in text)
        require(not missing, f"active source is missing M10-04 results in {relative}: " +
                ", ".join(missing))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-patch-application", action="store_true",
                        help="validate the contract without checking the pinned worktree")
    args = parser.parse_args()
    try:
        validate()
        if not args.skip_patch_application:
            check_patch_application()
        check_active_source()
    except (OSError, RebrandingError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Good Bear public product rebranding verified", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
