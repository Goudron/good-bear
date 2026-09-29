#!/usr/bin/env python3
"""Verify the GB100-M10-06 About author-link contract."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_build_context import SOURCE  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
PATCH_NAME = "0018-good-bear-about-author-links.patch"
PATCH_TARGETS = {"browser/base/content/aboutDialog.xhtml"}
AUTHOR_LINKS = {
    "goodbear-about-author-habr": (
        "Статьи автора на Хабре",
        "https://habr.com/ru/users/Goudron/articles/",
    ),
    "goodbear-about-author-support": (
        "Поддержать автора",
        "https://boosty.to/goodbear",
    ),
    "goodbear-about-author-hire": (
        "Пригласить автора на работу",
        "https://hh.ru/resume/08072c72ff0c8e15930039ed1f73616e327262",
    ),
    "goodbear-about-author-projects": (
        "Другие открытые проекты автора",
        "https://github.com/Goudron",
    ),
}


class AboutAuthorLinksError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AboutAuthorLinksError(message)


def series_entries(root: Path) -> list[str]:
    return [
        line.strip()
        for line in (root / "patches" / "series").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def patch_targets(patch_text: str) -> set[str]:
    return {
        line.removeprefix("+++ b/")
        for line in patch_text.splitlines()
        if line.startswith("+++ b/")
    }


def added_lines(patch_text: str) -> str:
    return "\n".join(
        line[1:]
        for line in patch_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )


def validate(
    root: Path = ROOT,
    *,
    patch_text: str | None = None,
    ftl_text: str | None = None,
) -> None:
    entries = series_entries(root)
    require(entries.count(PATCH_NAME) == 1, f"{PATCH_NAME} must occur exactly once in patches/series")
    require(entries.index(PATCH_NAME) > entries.index("0017-good-bear-approved-asset-injection.patch"),
            "M10-06 patch must follow M10-05 in patches/series")

    if patch_text is None:
        patch_text = (root / "patches" / PATCH_NAME).read_text(encoding="utf-8")
    require(patch_targets(patch_text) == PATCH_TARGETS, "About author-link patch target set changed")
    additions = added_lines(patch_text)
    for fluent_id, (label, url) in AUTHOR_LINKS.items():
        require(f'data-l10n-id="{fluent_id}"' in additions,
                f"About patch does not use {fluent_id}")
        require(f'href="{url}"' in additions,
                f"About patch does not use the exact target {url}")
        require(additions.count(f'href="{url}"') == (2 if fluent_id.endswith("habr") else 1),
                f"About patch has an unexpected number of {url} links")

    require('id="goodbearAuthorLinks"' in additions,
            "lower author links must not be controlled by the referral toggle")
    require("https://www.mozilla.org/?utm_source=firefox-browser" not in additions,
            "Mozilla project links must not remain in the About author-link surface")

    if ftl_text is None:
        ftl_text = (
            root
            / "overlay"
            / "browser"
            / "branding"
            / "goodbear"
            / "locales"
            / "en-US"
            / "brand.ftl"
        ).read_text(encoding="utf-8")
    for fluent_id, (label, _) in AUTHOR_LINKS.items():
        require(re.search(rf"^{re.escape(fluent_id)} = {re.escape(label)}$", ftl_text, re.MULTILINE) is not None,
                f"{fluent_id} must have the exact prescribed Russian label")
    require("Браузер создан на основе открытого исходного кода Mozilla Firefox." in ftl_text,
            "Mozilla attribution must remain")
    require("Good Bear — независимый браузер, не связанный с Mozilla." in ftl_text,
            "Mozilla non-affiliation must remain")


def check_patch_application(root: Path = ROOT) -> None:
    result = subprocess.run(
        ["git", "apply", "--check", "--whitespace=error-all", str(root / "patches" / PATCH_NAME)],
        cwd=SOURCE,
        text=True,
        capture_output=True,
        check=False,
    )
    require(result.returncode == 0, "About author-link patch does not apply cleanly: " +
            (result.stderr.strip() or result.stdout.strip()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-patch-application", action="store_true")
    args = parser.parse_args()
    try:
        validate()
        if not args.skip_patch_application:
            check_patch_application()
    except (OSError, AboutAuthorLinksError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Good Bear About author links verified", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
