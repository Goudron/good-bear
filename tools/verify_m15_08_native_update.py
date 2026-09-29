#!/usr/bin/env python3
"""Fail-closed M15-08 design gate; this does not verify a MAR signature."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))
from host_build_context import SOURCE as FIREFOX_SOURCE

VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*\Z")
URL_PART = re.compile(r"[A-Za-z0-9._+-]+\Z")


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path.name} must be an object")
    return value


def version(value: object) -> tuple[int, ...]:
    require(isinstance(value, str) and bool(VERSION.fullmatch(value)), "invalid version")
    components = [int(piece) for piece in value.split(".")]
    while len(components) > 1 and components[-1] == 0:
        components.pop()
    return tuple(components)


def verify_mar_public_cert_binding(root: Path = ROOT) -> None:
    """Check the pinned materialized updater's public MAR certificate selection.

    This is a source/input contract, not evidence that a signed MAR was built
    or verified at runtime.
    """
    manifest = load(root / "config/m15-08-signing-public-manifest.json")
    require(manifest.get("task") == "GB100-M15-08" and
            manifest.get("trust_model") == "exact pinned public certificates; no CA or TLS trust",
            "invalid MAR public certificate manifest")
    certificates = manifest.get("certificates")
    require(isinstance(certificates, list) and
            all(isinstance(item, dict) for item in certificates),
            "invalid MAR public certificate entries")
    by_role = {item.get("role"): item for item in certificates}
    require(len(by_role) == len(certificates) and
            {"mar-primary", "mar-backup"}.issubset(by_role),
            "MAR primary and backup public certificates must be pinned")

    source = root / FIREFOX_SOURCE.relative_to(ROOT)
    baseline = load(root / "config/firefox-baseline.json")
    source_version = (source / "browser/config/version.txt").read_text(encoding="utf-8").strip()
    require(source_version == baseline.get("version") == "156.0",
            "MAR source version differs from the pinned Firefox baseline")
    updater = source / "toolkit/mozapps/update/updater"
    mozbuild = (updater / "moz.build").read_text(encoding="utf-8")
    binding = (
        'if CONFIG["MOZ_UPDATE_CHANNEL"] == "goodbear":\n'
        '    primary_cert.inputs += ["goodbear_mar_primary.der"]\n'
        '    secondary_cert.inputs += ["goodbear_mar_backup.der"]\n'
        'elif CONFIG["MOZ_UPDATE_CHANNEL"] in ("beta", "release", "esr"):'
    )
    require(mozbuild.count(binding) == 1,
            "Good Bear MAR channel must select its own certificates before Mozilla release channels")
    for role, filename in (("mar-primary", "goodbear_mar_primary.der"),
                           ("mar-backup", "goodbear_mar_backup.der")):
        entry = by_role[role]
        declared = entry.get("certificate_der")
        require(isinstance(declared, str) and
                declared == f"third_party/goodbear-update-signing/{role}.der",
                f"{role}: unexpected public certificate path")
        pinned = (root / declared).read_bytes()
        selected = (updater / filename).read_bytes()
        require(pinned == selected and
                hashlib.sha256(selected).hexdigest() == entry.get("certificate_sha256"),
                f"{role}: materialized MAR certificate differs from the pinned public certificate")


def verify(root: Path = ROOT) -> None:
    """Assert that the current tree is a blocked, non-Mozilla update build."""
    contract = load(root / "config/m15-08-native-update-contract.json")
    identity = load(root / "config/product-identity.json")
    baseline = load(root / "config/firefox-baseline.json")
    mozconfig = (root / "overlay/build/goodbear/mozconfig").read_text(encoding="utf-8")

    require(contract.get("schema_version") == 1 and contract.get("task") == "GB100-M15-08",
            "invalid M15-08 contract")
    require(contract.get("implementation") == "Firefox Application Update",
            "native updater is required")
    pair = contract.get("version_pair", {})
    identity_pair = identity.get("version_pair", {})
    require(pair.get("product") == identity.get("product", {}).get("version") ==
            identity_pair.get("good_bear_version") == "1.0", "product version mismatch")
    require(pair.get("firefox_base") == identity_pair.get("firefox_base_version") ==
            identity.get("upstream_compatibility", {}).get("application_version", {}).get("value") ==
            baseline.get("version") == "156.0", "Firefox base mismatch")
    require(pair.get("ordering") ==
            "product version must increase; for equal product versions Firefox base must not decrease",
            "version ordering changed without review")
    channel = contract.get("channel")
    build = identity.get("build", {})
    require(channel == build.get("mar_channel_id") == "goodbear-release" and
            build.get("accepted_mar_channel_ids") == [channel], "MAR channel mismatch")
    require(identity.get("release", {}).get("channel") == "goodbear",
            "application update channel mismatch")
    require("ac_add_options --enable-update-channel=goodbear" in mozconfig and
            f"export MAR_CHANNEL_ID={channel}" in mozconfig and
            f"export ACCEPTED_MAR_CHANNEL_IDS={channel}" in mozconfig,
            "build update/MAR channel mismatch")

    transport = contract.get("transport", {})
    require(transport.get("metadata") == "HTTPS only" and
            transport.get("release_mapping") == "immutable GitHub Release tag and asset URLs only" and
            transport.get("complete_mar_required") is True and
            transport.get("partial_mar_allowed") is False, "unsafe update transport")
    trust = contract.get("trust", {})
    authority = trust.get("approved_signing_authority")
    require(isinstance(authority, str) and authority.startswith("Good Bear Project ") and
            trust.get("public_auto_update") ==
            "blocked pending source integration, signed end-to-end artifact verification, and release-channel review",
            "update authority or blocked-release gate changed")
    require(set(trust.get("required", [])) ==
            {"signed update metadata", "signed complete MAR", "pinned product and channel",
             "key rotation record"}, "missing update trust requirement")
    require(set(trust.get("reject", [])) ==
            {"unsigned", "wrong product", "wrong channel", "replay", "downgrade",
             "modified MAR", "Firefox-base mismatch", "platform mismatch",
            "unapproved or unpinned self-issued trust"}, "missing update rejection")
    privacy = contract.get("privacy", {})
    require(set(privacy.get("allowed_update_fields", [])) ==
            {"product version", "Firefox base version", "platform", "channel"} and
            set(privacy.get("forbidden", [])) ==
            {"browsing history", "profile data", "container state", "certificate history"},
            "update privacy boundary changed")
    require(contract.get("failure_mode") ==
            "non-fatal fail closed; retain the installed version and surface a local error",
            "update failure mode changed")

    service = identity.get("services", {}).get("application_updater", {})
    require(service.get("enabled") is False and service.get("endpoints") == [],
            "public application updater must remain disabled")
    require("ac_add_options --disable-updater" in mozconfig and
            "ac_add_options --enable-updater" not in mozconfig and
            "--enable-unverified-updates" not in mozconfig and
            "MOZ_APPUPDATE_HOST" not in mozconfig,
            "updater or unverified/Mozilla endpoint enabled before source integration")
    verify_mar_public_cert_binding(root)


def release_asset(url: object, tag: str, suffix: str) -> tuple[str, str]:
    """Validate URL shape only. GitHub tag immutability requires separate evidence."""
    require(isinstance(url, str), "release URL missing")
    parsed = urlsplit(url)
    parts = parsed.path.strip("/").split("/")
    require(parsed.scheme == "https" and parsed.netloc == "github.com" and
            not parsed.query and not parsed.fragment and
            len(parts) == 6 and parts[2:4] == ["releases", "download"] and
            all(URL_PART.fullmatch(part) and part not in (".", "..") for part in parts) and
            parts[4] == tag and parts[5].endswith(suffix),
            "release asset must use a pinned HTTPS GitHub Release URL")
    return parts[0], parts[1]


def validate_offer_policy(candidate: dict, installed: dict, contract: dict) -> None:
    """Validate eligibility only; never authorizes installation or authenticates metadata."""
    require(candidate.get("product") == "Good Bear" and
            candidate.get("product") == installed.get("product"), "wrong product")
    require(candidate.get("channel") == contract.get("channel") ==
            installed.get("channel"), "wrong channel")
    require(candidate.get("platform") == installed.get("platform") == "win64",
            "platform mismatch")
    require(candidate.get("mar_type") == "complete", "partial or missing MAR")
    require(candidate.get("app_version") == candidate.get("firefox_base_version") and
            candidate.get("mar_product_version") == candidate.get("firefox_base_version"),
            "Firefox-base mismatch")
    require(version(candidate.get("product_version")) >
            version(installed.get("product_version")), "replay or product downgrade")
    require(version(candidate.get("firefox_base_version")) >=
            version(installed.get("firefox_base_version")), "Firefox-base downgrade")
    tag = candidate.get("release_tag")
    require(isinstance(tag, str) and VERSION.fullmatch(candidate["product_version"]) is not None
            and candidate["product_version"] in tag and
            candidate["firefox_base_version"] in tag,
            "release tag must identify both versions")
    metadata_repo = release_asset(candidate.get("metadata_url"), tag, ".xml")
    mar_repo = release_asset(candidate.get("mar_url"), tag, ".mar")
    require(metadata_repo == mar_repo, "metadata and MAR release differ")
    digest = candidate.get("mar_sha512")
    require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{128}", digest) is not None,
            "MAR SHA-512 missing or invalid")


def verify_mar_hash(data: bytes, expected_sha512: str) -> None:
    require(isinstance(data, bytes) and
            hashlib.sha512(data).hexdigest() == expected_sha512,
            "modified MAR or SHA-512 mismatch")


def authorize_public_update(candidate: dict, installed: dict, contract: dict) -> None:
    validate_offer_policy(candidate, installed, contract)
    # A hash or a claimed "signed" field is not a signature verification.
    raise ContractError(
        "public auto-update blocked: source integration and end-to-end cryptographic verification pending"
    )


def main() -> int:
    try:
        verify()
    except (ContractError, OSError, ValueError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("M15-08 native update design verified; public auto-update BLOCKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
