#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Generate and verify the GB100-M10-07 release-source inventory."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import ssl
import subprocess
import sys
from typing import Iterable

from host_build_context import SOURCE


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "config/m10-07-source-release-inventory.json"
L10N_ROOT = ROOT / "source/l10n/firefox-l10n"
REQUIRED_COMPONENT_IDS = {
    "mozilla-firefox-upstream-and-vendored-materials",
    "good-bear-software-and-build-inputs",
    "mozilla-russian-localization-with-good-bear-messages",
    "good-bear-original-artwork",
    "russian-pki-certificates",
    "fstec-public-leaf-test-fixture",
    "ubuntu-build-toolchain",
}
REQUIRED_COMPONENT_FIELDS = {
    "id",
    "kind",
    "owner",
    "license",
    "source",
    "modification_status",
    "redistribution_status",
}
EXPECTED_PUBLIC_BLOCKERS = {
    "good_bear_revision_unavailable",
}
LEGAL_TARGET = re.compile(
    r"(^|/)(license|licenses|notice|notices|third[_-]?party)([./]|$)", re.IGNORECASE
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class SourceInventoryError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SourceInventoryError(message)


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceInventoryError(f"cannot load {path}: {exc}") from exc
    require(isinstance(value, dict), f"{path}: expected a JSON object")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def manifest_digest(root: Path, paths: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(root).as_posix()
        digest.update(f"{sha256(path)}  {relative}\n".encode("utf-8"))
    return digest.hexdigest()


def series_entries(root: Path) -> list[str]:
    return [
        line.strip()
        for line in (root / "patches/series").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def patch_targets(patch: Path) -> set[str]:
    return {
        line.removeprefix("+++ b/")
        for line in patch.read_text(encoding="utf-8").splitlines()
        if line.startswith("+++ b/")
    }


def overlay_files(root: Path, excluded: set[str]) -> list[Path]:
    files = sorted(path for path in (root / "overlay").rglob("*") if path.is_file())
    return [path for path in files if path.relative_to(root).as_posix() not in excluded]


def artwork_files(root: Path) -> list[Path]:
    return sorted(
        path for path in (root / "artwork/final/m10-03").rglob("*") if path.is_file()
    )


def git_output(cwd: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, text=True, capture_output=True, check=False
    )
    if check and result.returncode:
        raise SourceInventoryError(
            f"git {' '.join(args)} failed: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout.rstrip("\n") if result.returncode == 0 else ""


def l10n_changes(root: Path, records: list[dict]) -> list[dict]:
    require((root / ".git").exists(), "pinned Russian localization repository is missing")
    declared_paths = {record.get("path") for record in records}
    require(all(isinstance(path, str) and path for path in declared_paths),
            "Russian localization modification path is missing")
    status = git_output(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        "ru",
    )
    actual_status: dict[str, str] = {}
    for line in status.splitlines():
        require(len(line) > 3, f"cannot parse localization status: {line!r}")
        code = line[:2]
        relative = line[3:]
        require(" -> " not in relative, "renamed localization files require an explicit review")
        require(code in {" M", "M ", "??"},
                f"unsupported localization modification status {code!r}: {relative}")
        actual_status[relative] = "added" if code == "??" else "modified"
    require(set(actual_status) == declared_paths,
            "Russian localization modifications differ from the release inventory")

    generated: list[dict] = []
    for record in records:
        relative = record["path"]
        path = root / relative
        require(path.is_file(), f"Russian localization source is missing: {relative}")
        require(record.get("status") == actual_status[relative],
                f"Russian localization modification status drift: {relative}")
        actual_hash = sha256(path)
        require(record.get("sha256") == actual_hash,
                f"Russian localization source hash drift: {relative}")
        generated.append({"path": relative, "status": actual_status[relative], "sha256": actual_hash})
    return generated


def validate(
    root: Path = ROOT,
    *,
    inventory: dict | None = None,
    repository_revision: str | None = None,
) -> dict:
    inventory = copy.deepcopy(inventory) if inventory is not None else load_json(
        root / "config/m10-07-source-release-inventory.json"
    )
    require(inventory.get("schema_version") == 1, "unsupported M10-07 schema")
    require(inventory.get("milestone") == "GB100-M10-07", "wrong M10-07 milestone")

    scope = inventory.get("release_scope", {})
    identity = load_json(root / "config/product-identity.json")
    require(scope.get("product_name") == "Good Bear" and
            scope.get("public_branding") == "Good Bear",
            "public product identity must remain Good Bear")
    require(scope.get("shipped_locales") == ["ru"] and
            identity.get("release", {}).get("shipped_locales") == ["ru"],
            "the source inventory must describe the Russian-only product")
    require(scope.get("upstream_attribution_is_product_branding") is False,
            "Mozilla attribution must not become Good Bear product branding")

    source = inventory.get("corresponding_source", {})
    upstream = source.get("upstream", {})
    baseline = load_json(root / "config/firefox-baseline.json")
    require(upstream.get("version") == baseline.get("version") and
            upstream.get("revision") == baseline.get("vcs", {}).get("revision"),
            "corresponding source uses the wrong Firefox revision")
    require(upstream.get("source_url") == baseline.get("source", {}).get("archive_url") and
            upstream.get("archive_sha256") == baseline.get("source", {}).get("sha256"),
            "corresponding source uses the wrong Firefox source archive")
    require("MPL-2.0" in upstream.get("license", "") and
            "third-party" in upstream.get("license", ""),
            "upstream source license/provenance is incomplete")

    patch_set = source.get("patch_set", {})
    entries = series_entries(root)
    require(entries == patch_set.get("entries"), "ordered patch inventory differs from patches/series")
    patch_paths = [root / "patches/series", *(root / "patches" / entry for entry in entries)]
    require(all(path.is_file() for path in patch_paths), "an inventoried source patch is missing")
    unlisted = {path.name for path in (root / "patches").glob("*.patch")} - set(entries)
    require(not unlisted, "unlisted Good Bear source patches: " + ", ".join(sorted(unlisted)))
    actual_patch_digest = manifest_digest(root, patch_paths)
    require(patch_set.get("manifest_sha256") == actual_patch_digest,
            "exact Good Bear patch-set manifest drift")
    for patch in patch_paths[1:]:
        forbidden_targets = sorted(target for target in patch_targets(patch) if LEGAL_TARGET.search(target))
        require(not forbidden_targets,
                f"{patch.name} rewrites protected legal/notice paths: " + ", ".join(forbidden_targets))

    overlay = source.get("overlay", {})
    excluded = set(overlay.get("excluded_control_files", []))
    require(excluded == {"overlay/.gitkeep"}, "overlay exclusion may contain only its empty marker")
    overlay_paths = overlay_files(root, excluded)
    actual_overlay_digest = manifest_digest(root, overlay_paths)
    require(overlay.get("manifest_sha256") == actual_overlay_digest,
            "exact Good Bear overlay manifest drift")

    localization = source.get("russian_localization", {})
    require(localization.get("repository") ==
            git_output(root / "source/l10n/firefox-l10n", "remote", "get-url", "origin"),
            "Russian localization source repository drift")
    require(localization.get("base_revision") ==
            git_output(root / "source/l10n/firefox-l10n", "rev-parse", "HEAD"),
            "Russian localization base revision drift")
    generated_l10n = l10n_changes(
        root / "source/l10n/firefox-l10n", localization.get("modifications", [])
    )

    fixtures = source.get("test_certificate_fixtures")
    require(isinstance(fixtures, list) and len(fixtures) == 1,
            "exactly one reviewed public leaf test fixture is required")
    fixture = fixtures[0]
    fixture_path = root / fixture.get("path", "missing")
    require(fixture_path == root / SOURCE.relative_to(ROOT) /
            "security/manager/ssl/tests/gtest/goodbear-russian-pki/fstec-rsa2024-leaf.pem",
            "FSTEC fixture must use the current canonical Firefox source")
    require(fixture.get("source_endpoint") == "https://fstec.ru:443" and
            fixture.get("role") == "public_leaf_test_fixture",
            "FSTEC fixture source/role provenance drift")
    require(fixture.get("trust_input") is False and fixture.get("binary_packaging") is False,
            "the public FSTEC leaf must remain source-only test data, never trust or binary input")
    require(fixture_path.is_file() and sha256(fixture_path) == fixture.get("pem_sha256"),
            "FSTEC public leaf PEM hash drift")
    try:
        fixture_der = ssl.PEM_cert_to_DER_cert(fixture_path.read_text(encoding="ascii"))
    except (OSError, ValueError) as exc:
        raise SourceInventoryError(f"cannot decode FSTEC public leaf fixture: {exc}") from exc
    require(hashlib.sha256(fixture_der).hexdigest() == fixture.get("certificate_der_sha256"),
            "FSTEC public leaf DER hash drift")
    require("approved" in fixture.get("redistribution_status", "") and
            "source-only" in fixture.get("redistribution_status", ""),
            "FSTEC public leaf redistribution disposition is incomplete")
    require(fixture_path.name in
            (root / "patches/0019-good-bear-fstec-native-scope-regression.patch").read_text(encoding="utf-8"),
            "FSTEC public leaf is absent from the corresponding patch source")

    artwork = load_json(root / "config/m10-03-artwork-system.json")
    injection = load_json(root / "config/m10-05-asset-injection.json")
    rights = artwork.get("rights", {})
    require(rights.get("copyright") ==
            "Copyright © 2026 Valery Ledovskoy <valery@ledovskoy.com>" and
            rights.get("license") == "All rights reserved unless otherwise stated.",
            "Good Bear artwork owner/license record is incomplete")
    require(rights.get("input_images") == [] and
            rights.get("third_party_or_upstream_art_used") is False,
            "Good Bear release artwork has unresolved input provenance")
    require(artwork.get("selected_direction") == injection.get("selected_variant_id"),
            "selected artwork direction and release injection disagree")
    generated_artwork = [
        {"path": path.relative_to(root).as_posix(), "sha256": sha256(path)}
        for path in artwork_files(root)
    ]
    require(generated_artwork, "approved Good Bear artwork source set is empty")

    components = inventory.get("components")
    require(isinstance(components, list), "component provenance inventory is missing")
    require({component.get("id") for component in components} == REQUIRED_COMPONENT_IDS,
            "component provenance inventory is incomplete")
    for component in components:
        require(set(component) == REQUIRED_COMPONENT_FIELDS,
                f"{component.get('id')}: owner/license/source/modification/redistribution fields are required")
        require(all(isinstance(component[field], str) and component[field].strip()
                    for field in REQUIRED_COMPONENT_FIELDS),
                f"{component.get('id')}: empty provenance field")

    certificate = load_json(root / "config/m3-01-certificate-provenance.json")
    redistribution = certificate.get("redistribution", {})
    disposition = certificate.get("disposition", {})
    require(redistribution.get("status") == "approved_for_binary_redistribution" and
            redistribution.get("explicit_third_party_redistribution_grant_found") is True,
            "certificate binary redistribution approval is missing")
    require(disposition.get("mode") == "controlled_official_source_import_with_binary_bundle" and
            disposition.get("bundle_certificate_bytes") is True and
            disposition.get("commit_certificate_bytes") is False and
            disposition.get("runtime_download") is False,
            "certificate bundle must remain controlled, non-committed, and non-runtime")

    legal = inventory.get("legal_surfaces", {})
    for key, relative in {
        "bundled_notice_route_owner": "docshell/base/nsAboutRedirector.cpp",
        "bundled_notice_owner": "toolkit/content/license.html",
        "bundled_notice_packaging_owner": "toolkit/content/jar.mn",
    }.items():
        require(root / legal.get(key, "missing") == root / SOURCE.relative_to(ROOT) / relative,
                "legal notice owners must use the current canonical Firefox source")
    notice_route = (root / legal.get("bundled_notice_route_owner", "missing")).read_text(
        encoding="utf-8"
    )
    notice_packaging = (root / legal.get("bundled_notice_packaging_owner", "missing")).read_text(
        encoding="utf-8"
    )
    branding_ftl = (root / "overlay/browser/branding/goodbear/locales/en-US/brand.ftl").read_text(
        encoding="utf-8"
    )
    require(legal.get("bundled_notice_entrypoint") == "about:license" and
            '{"license", "chrome://global/content/license.html"' in notice_route and
            "content/global/license.html" in notice_packaging and
            (root / legal.get("bundled_notice_owner", "missing")).is_file(),
            "bundled upstream/third-party legal notices are not internally reachable")
    require(legal.get("about_attribution") in branding_ftl,
            "descriptive Mozilla Firefox source attribution is missing")
    require(legal.get("mozilla_non_affiliation") in branding_ftl,
            "Mozilla non-affiliation notice is missing")
    require(legal.get("preserve_upstream_and_third_party_notices") is True,
            "legal notice preservation must be mandatory")

    offer = source.get("source_offer", {})
    require(offer.get("terms_must_not_restrict_mpl_source_code_form") is True,
            "source-offer terms must preserve MPL Source Code Form rights")
    for relative in offer.get("required_inputs", []):
        if "*" not in relative:
            require((root / relative).exists(), f"source-offer input is missing: {relative}")

    if repository_revision is None:
        repository_revision = git_output(root, "rev-parse", "--verify", "HEAD", check=False) or None
    recorded_revision = source.get("good_bear_revision", {}).get("value")
    blockers: set[str] = set()
    if repository_revision is None or recorded_revision is None:
        blockers.add("good_bear_revision_unavailable")
    else:
        require(recorded_revision == repository_revision,
                "recorded Good Bear revision differs from the source repository")
    if offer.get("location") != "https://github.com/Goudron/good-bear":
        blockers.add("source_offer_location_unset")
    if redistribution.get("status") != "approved_for_binary_redistribution":
        blockers.add("certificate_binary_redistribution_unresolved")

    gate = inventory.get("public_release_gate", {})
    require(gate.get("allowed") is False, "current unresolved inputs must block public artifacts")
    require(set(gate.get("required_blockers", [])) == EXPECTED_PUBLIC_BLOCKERS,
            "public release blocker policy is incomplete")
    require(blockers == EXPECTED_PUBLIC_BLOCKERS,
            "recorded public release blockers differ from actual unresolved inputs")

    return {
        "schema_version": 1,
        "milestone": "GB100-M10-07",
        "product": "Good Bear",
        "shipped_locales": ["ru"],
        "version_pair": identity["version_pair"],
        "upstream_version": upstream["version"],
        "upstream_revision": upstream["revision"],
        "upstream_source_url": upstream["source_url"],
        "upstream_archive_sha256": upstream["archive_sha256"],
        "good_bear_revision": repository_revision,
        "patch_set": {
            "manifest_sha256": actual_patch_digest,
            "files": [
                {"path": path.relative_to(root).as_posix(), "sha256": sha256(path)}
                for path in patch_paths
            ],
        },
        "overlay": {
            "manifest_sha256": actual_overlay_digest,
            "files": [
                {"path": path.relative_to(root).as_posix(), "sha256": sha256(path)}
                for path in overlay_paths
            ],
        },
        "russian_localization": generated_l10n,
        "artwork": generated_artwork,
        "components": components,
        "certificate_disposition": {
            "redistribution": redistribution["status"],
            "mode": disposition["mode"],
            "bundle_certificate_bytes": disposition["bundle_certificate_bytes"],
        },
        "legal_notice_entrypoint": "about:license",
        "public_release_allowed": False,
        "public_release_blockers": sorted(blockers),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, help="write the generated exact inventory as JSON")
    parser.add_argument("--public-release", action="store_true",
                        help="require every public-release blocker to be resolved")
    args = parser.parse_args()
    try:
        report = validate()
        if args.public_release and report["public_release_blockers"]:
            raise SourceInventoryError(
                "public release blocked: " + ", ".join(report["public_release_blockers"])
            )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
    except (OSError, SourceInventoryError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        "Good Bear M10-07 source/provenance inventory verified; public release blocked: "
        + ", ".join(report["public_release_blockers"]),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
