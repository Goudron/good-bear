#!/usr/bin/env python3
"""Fail closed when a public Good Bear release lacks approved artwork."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_build_context import FIREFOX_WORKTREE_NAME, SOURCE  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
PATCH_NAME = "0017-good-bear-approved-asset-injection.patch"
PATCH_TARGETS = {"browser/branding/branding-common.mozbuild"}
REQUIRED_ICON_SIZES = {16, 32, 48, 64, 128}
FORBIDDEN_ARTWORK_TOKENS = ("firefox", "mozilla", "placeholder")
REQUIRED_CONTENT_MAPPINGS = {
    "content/branding/about.png                         (../default128.png)",
    "content/branding/about-logo.png                    (../default128.png)",
    "content/branding/about-logo@2x.png                 (../default128.png)",
    "content/branding/about-logo-private.png            (../default128.png)",
    "content/branding/about-logo-private@2x.png         (../default128.png)",
    "content/branding/icon16.png                         (../default16.png)",
    "content/branding/icon32.png                         (../default32.png)",
    "content/branding/icon48.png                         (../default48.png)",
    "content/branding/icon64.png                         (../default64.png)",
    "content/branding/icon128.png                        (../default128.png)",
}
REQUIRED_PATCH_ADDITIONS = {
    'elif CONFIG["MOZ_BRANDING_DIRECTORY"] == "browser/branding/goodbear":',
    '"default16.png",',
    '"default32.png",',
    '"default48.png",',
    '"default64.png",',
    '"default128.png",',
}
REQUIRED_UNMAPPED_MASCOT_ASSETS = {
    "overlay/browser/components/aboutwelcome/assets/goodbear-empty-state.png",
    "overlay/browser/components/aboutwelcome/assets/goodbear-generic-error.png",
}
ACTIVE_SOURCE_REQUIREMENTS = {
    "browser/branding/branding-common.mozbuild": REQUIRED_PATCH_ADDITIONS,
    "browser/branding/goodbear/moz.build": {'DIRS += ["content", "locales"]'},
    "browser/branding/goodbear/content/jar.mn": REQUIRED_CONTENT_MAPPINGS,
}


class AssetInjectionError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssetInjectionError(message)


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssetInjectionError(f"cannot load {path}: {exc}") from exc
    require(isinstance(value, dict), f"{path}: expected JSON object")
    return value


def module_from(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def added_lines(patch_text: str) -> set[str]:
    return {
        line[1:].strip()
        for line in patch_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    }


def validate_patch_order(entries: list[str]) -> None:
    require(entries.count(PATCH_NAME) == 1,
            "M10-05 injection patch must occur exactly once in the patch series")
    rebranding_patch = "0016-good-bear-public-product-rebranding.patch"
    require(rebranding_patch in entries and
            entries.index(PATCH_NAME) == entries.index(rebranding_patch) + 1,
            "M10-05 injection patch must immediately follow M10-04 rebranding")


def validate(
    root: Path = ROOT,
    *,
    gate: dict | None = None,
    identity: dict | None = None,
    patch_text: str | None = None,
) -> None:
    gate = copy.deepcopy(gate) if gate is not None else load_json(
        root / "config" / "m10-05-asset-injection.json"
    )
    identity = copy.deepcopy(identity) if identity is not None else load_json(
        root / "config" / "product-identity.json"
    )
    require(gate.get("schema_version") == 1, "unsupported M10-05 asset gate schema")
    require(gate.get("milestone") == "GB100-M10-05", "wrong M10-05 milestone")
    require(gate.get("release_mode") == "public_release", "asset gate must govern public releases")
    release_gate = gate.get("release_gate")
    require(isinstance(release_gate, dict), "release gate record is missing")
    require(release_gate == {
        "fail_closed": True,
        "development_placeholders_allowed": True,
        "public_release_placeholders_allowed": False,
        "firefox_or_mozilla_derived_art_allowed": False,
        "unapproved_art_allowed": False,
        "required_locale": "ru",
        "required_shipped_locales": ["ru"],
    }, "public artwork gate must remain fail-closed")

    candidates = load_json(root / "config" / "m10-02-visual-candidates.json")
    artwork = load_json(root / "config" / "m10-03-artwork-system.json")
    selected = gate.get("selected_variant_id")
    require(selected == "workshop-beacon", "M10-05 selected variant is not Workshop Beacon")
    require(candidates.get("selection_gate", {}).get("selected_candidate_id") == selected,
            "M10-02 selection and M10-05 injection disagree")
    require(artwork.get("selected_direction") == selected,
            "M10-03 approval and M10-05 injection disagree")

    artwork_verifier = module_from(root / "tools" / "verify_m10_03_artwork_system.py", "m10_05_artwork")
    try:
        artwork_verifier.validate(artwork, root)
    except Exception as exc:
        raise AssetInjectionError(f"approved M10-03 artwork failed verification: {exc}") from exc

    expected_sources = gate.get("approved_source_assets")
    require(isinstance(expected_sources, dict), "approved source artwork digests are missing")
    source_paths = {"master": artwork.get("master")}
    source_paths.update(artwork.get("state_assets", {}))
    require(set(expected_sources) == set(source_paths), "approved source artwork set is incomplete")
    for state, relative in source_paths.items():
        require(isinstance(relative, str), f"{state}: approved source path is missing")
        path = root / relative
        require(path.is_file(), f"{state}: approved source asset is missing")
        require(sha256(path) == expected_sources[state], f"{state}: approved source digest differs")

    icons = gate.get("ubuntu_icons")
    require(isinstance(icons, dict) and {int(size) for size in icons} == REQUIRED_ICON_SIZES,
            "full Ubuntu icon-size set is required")
    for raw_size, expected_digest in icons.items():
        size = int(raw_size)
        path = root / "overlay" / "browser" / "branding" / "goodbear" / f"default{size}.png"
        require(path.is_file(), f"Ubuntu icon {size} is missing")
        require(artwork_verifier.png_size(path) == (size, size), f"Ubuntu icon {size} has wrong dimensions")
        require(sha256(path) == expected_digest, f"Ubuntu icon {size} differs from approved injection")

    injected = gate.get("injected_surface_assets")
    replacements = artwork.get("surface_replacements")
    require(isinstance(injected, dict) and isinstance(replacements, list),
            "injected mascot surface record is missing")
    replacement_paths = {item.get("replacement") for item in replacements if isinstance(item, dict)}
    require(set(injected) == replacement_paths | REQUIRED_UNMAPPED_MASCOT_ASSETS,
            "every audited mascot surface and required generic state must have exactly one approved injected asset")
    for relative, expected_digest in injected.items():
        require(isinstance(relative, str) and relative.startswith("overlay/"),
                "injected asset must be a Good Bear overlay path")
        require(not any(token in Path(relative).name.lower() for token in FORBIDDEN_ARTWORK_TOKENS),
                f"{relative}: forbidden public artwork token")
        path = root / relative
        require(path.is_file(), f"{relative}: injected asset is missing")
        require(sha256(path) == expected_digest, f"{relative}: injected asset differs from approved artwork")

    content = root / "overlay" / "browser" / "branding" / "goodbear" / "content"
    jar = (content / "jar.mn").read_text(encoding="utf-8")
    require(REQUIRED_CONTENT_MAPPINGS <= {line.strip() for line in jar.splitlines()},
            "public About/logo icon slots are incomplete")
    for relative in ("moz.build", "jar.mn", "about-logo.svg", "about-wordmark.svg", "aboutDialog.css"):
        path = content / relative
        require(path.is_file(), f"public branding content slot is missing: {relative}")
    for relative in ("about-logo.svg", "about-wordmark.svg"):
        lowered = (content / relative).read_text(encoding="utf-8").lower()
        require(not any(token in lowered for token in FORBIDDEN_ARTWORK_TOKENS),
                f"{relative}: forbidden public artwork token")
    require('href="icon128.png"' in (content / "about-logo.svg").read_text(encoding="utf-8"),
            "About logo must resolve through the approved icon128 slot")
    require("Good Bear" in (content / "about-wordmark.svg").read_text(encoding="utf-8"),
            "About wordmark must use the Good Bear public name")

    release = identity.get("release")
    art_identity = identity.get("artwork")
    require(isinstance(release, dict) and isinstance(art_identity, dict), "product identity release/artwork record is missing")
    require(release.get("platform") == "ubuntu" and release.get("architecture") == "amd64",
            "M10-05 public artwork gate is limited to Ubuntu amd64")
    require(release.get("locale") == release_gate["required_locale"] and
            release.get("shipped_locales") == release_gate["required_shipped_locales"],
            "public release must ship Russian resources only")
    require(art_identity.get("release_status") == "approved_original_assets_verified_by_m10_05" and
            art_identity.get("selected_variant_id") == selected and
            art_identity.get("release_gate") == "tools/verify_m10_05_asset_injection.py",
            "product identity does not point at the approved artwork release gate")
    strict_locale_patch = (root / "patches" / "0015-good-bear-strict-russian-release-locale.patch").read_text(encoding="utf-8")
    build_wrapper = (root / "tools" / "build_host_russian.py").read_text(encoding="utf-8")
    require("GOODBEAR_RUSSIAN_ONLY" in strict_locale_patch and
            "GOODBEAR_RUSSIAN_ONLY" in build_wrapper and "installers-ru" in build_wrapper,
            "Russian-only repack boundary is missing")

    rebranding = module_from(root / "tools" / "verify_public_rebranding.py", "m10_05_rebranding")
    try:
        rebranding.validate(root)
    except Exception as exc:
        raise AssetInjectionError(f"M10-04 public rebranding or attribution regressed: {exc}") from exc

    validate_patch_order(series_entries(root))
    if patch_text is None:
        patch_text = (root / "patches" / PATCH_NAME).read_text(encoding="utf-8")
    require(patch_targets(patch_text) == PATCH_TARGETS, "asset injection patch target set changed")
    require(REQUIRED_PATCH_ADDITIONS <= added_lines(patch_text),
            "asset injection patch no longer binds every Ubuntu icon size")


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
    require(result.returncode == 0, "asset injection patch does not apply to pristine source: " +
            (result.stderr.strip() or result.stdout.strip()))


def active_source_texts(root: Path = ROOT) -> dict[str, str]:
    source = SOURCE
    texts = {}
    for relative in ACTIVE_SOURCE_REQUIREMENTS:
        try:
            texts[relative] = (source / relative).read_text(encoding="utf-8")
        except OSError as exc:
            raise AssetInjectionError(f"cannot read active M10-05 owner {relative}: {exc}") from exc
    return texts


def expected_active_asset_digests(root: Path = ROOT) -> dict[str, str]:
    gate = load_json(root / "config" / "m10-05-asset-injection.json")
    expected = {
        f"browser/branding/goodbear/default{size}.png": digest
        for size, digest in gate["ubuntu_icons"].items()
    }
    expected.update({relative.removeprefix("overlay/"): digest
                     for relative, digest in gate["injected_surface_assets"].items()})
    return expected


def active_asset_digests(root: Path = ROOT) -> dict[str, str]:
    source = SOURCE
    expected = expected_active_asset_digests(root)
    actual = {}
    for relative in expected:
        path = source / relative
        try:
            actual[relative] = sha256(path)
        except OSError as exc:
            raise AssetInjectionError(f"active injected asset is missing: {relative}: {exc}") from exc
    return actual


def check_active_source(
    root: Path = ROOT,
    *,
    texts: dict[str, str] | None = None,
    asset_digests: dict[str, str] | None = None,
) -> None:
    if texts is None:
        texts = active_source_texts(root)
    for relative, required_fragments in ACTIVE_SOURCE_REQUIREMENTS.items():
        text = texts.get(relative, "")
        missing = sorted(fragment for fragment in required_fragments if fragment not in text)
        require(not missing, f"active source is missing M10-05 injection results in {relative}: " +
                ", ".join(missing))

    expected = expected_active_asset_digests(root)
    if asset_digests is None:
        asset_digests = active_asset_digests(root)
    for relative, expected_digest in expected.items():
        require(asset_digests.get(relative) == expected_digest,
                f"active injected asset differs from approved artwork: {relative}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-patch-application", action="store_true")
    args = parser.parse_args()
    try:
        validate()
        if not args.skip_patch_application:
            check_patch_application()
        check_active_source()
    except (OSError, AssetInjectionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Good Bear M10-05 approved asset injection verified", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
