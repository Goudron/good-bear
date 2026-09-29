#!/usr/bin/env python3
"""Verify the fail-closed Firefox 155 -> 156 -> 157 UI watch state."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
from itertools import product
import json
from pathlib import Path
import re
import struct
import sys
import zlib


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "m15-11-upstream-ui-watch.json"
BADGE_PATCH = "patches/0024-good-bear-trust-panel-russian-pki-ru-badge.patch"
IDENTITY_CSS = "browser/themes/shared/identity-block/identity-block.css"
SHIELD_OWNERS = {IDENTITY_CSS} | {
    f"browser/themes/shared/identity-block/trust-icon-{state}.svg"
    for state in ("active", "disabled", "insecure", "warning")
}


class WatchError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise WatchError(message)


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WatchError(f"cannot read {path}: {exc}") from exc
    require(isinstance(value, dict), f"{path} must contain an object")
    return value


def verify_ru_shield_source(source: Path, audit: dict, root: Path = ROOT) -> None:
    """Check inherited shield assets/CSS; this is not a rendered UI check."""
    patch = (root / BADGE_PATCH).read_text(encoding="utf-8")
    css_patch = patch.split(f"+++ b/{IDENTITY_CSS}\n", 1)[1]
    addition = "".join(line[1:] + "\n" for line in css_patch.splitlines()
                       if line.startswith("+") and not line.startswith("+++"))
    for owner, expected in audit["unchanged_owner_sha256"].items():
        content = (source / owner).read_bytes()
        if owner == IDENTITY_CSS:
            require(content.count(addition.encode()) == 1,
                    "RU badge CSS is absent, duplicated or changed")
            content = content.replace(addition.encode(), b"", 1)
        require(hashlib.sha256(content).hexdigest() == expected,
                f"upstream shield owner changed without review: {owner}")


def current_fluent_audit(source: Path | None = None) -> dict:
    from verify_m15_11_fluent_audit import audit
    return audit(source=source) if source is not None else audit()


def evidence_file(root: Path, record: dict, label: str) -> Path:
    require(isinstance(record, dict), f"{label} must be a hashed artifact record")
    relative, digest = record.get("path"), record.get("sha256")
    require(isinstance(relative, str) and relative.startswith("artifacts/"),
            f"{label} must name a project artifact")
    path = (root / relative).resolve()
    require(path.is_relative_to((root / "artifacts").resolve()) and path.is_file(),
            f"{label} artifact is missing or escapes the artifact directory")
    require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest),
            f"{label} lacks a SHA-256 digest")
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    require(actual == digest, f"{label} artifact hash mismatch")
    return path


def verify_capture_png(path: Path, scale: float) -> None:
    """Validate browser PNG bytes, geometry and scanline size, not UI appearance."""
    with path.open("rb") as stream:
        require(stream.read(8) == b"\x89PNG\r\n\x1a\n", "visual artifact is not PNG")
        compressed, dimensions, channels = bytearray(), None, None
        while True:
            raw_length = stream.read(4)
            require(len(raw_length) == 4, "visual PNG is truncated")
            length = struct.unpack(">I", raw_length)[0]
            require(length <= 32 * 1024 * 1024, "visual PNG chunk is oversized")
            kind, data, crc = stream.read(4), stream.read(length), stream.read(4)
            require(len(data) == length and len(crc) == 4 and
                    zlib.crc32(kind + data) == struct.unpack(">I", crc)[0],
                    "visual PNG chunk is truncated or corrupt")
            if dimensions is None:
                require(kind == b"IHDR" and length == 13, "visual PNG lacks IHDR")
                width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", data)
                require((width, height) == (round(1920 * scale), round(1080 * scale)),
                        "visual PNG dimensions do not match its declared viewport and scale")
                require(depth == 8 and color in {2, 6} and
                        compression == filtering == interlace == 0,
                        "visual PNG is not an ordinary browser RGB/RGBA capture")
                dimensions, channels = (width, height), 3 if color == 2 else 4
            elif kind == b"IDAT":
                compressed.extend(data)
                require(len(compressed) <= 32 * 1024 * 1024, "visual PNG data is oversized")
            elif kind == b"IEND":
                require(length == 0 and not stream.read(1), "visual PNG has trailing data")
                break
            else:
                require(kind != b"IHDR", "visual PNG has duplicate IHDR")
    expected = (dimensions[0] * channels + 1) * dimensions[1]
    try:
        decoder = zlib.decompressobj()
        pixels = decoder.decompress(compressed, expected + 1)
    except zlib.error as exc:
        raise WatchError("visual PNG image data is corrupt") from exc
    require(len(pixels) == expected and decoder.eof and not decoder.unused_data,
            "visual PNG scanline data is incomplete or oversized")


def verify_reviewed_evidence(root: Path, contract: dict, transition: dict,
                             source: Path | None = None) -> None:
    """Bind successful review to current source and complete, existing artifacts."""
    fluent_ref = transition.get("fluent_audit")
    fluent = load(evidence_file(root, fluent_ref, "Fluent audit"))
    actual = current_fluent_audit(source)
    require(actual.get("status") == fluent.get("status") == "passed",
            "reviewed Fluent audit has unresolved findings")
    for field in ("method", "source_manifest_sha256", "owner_sha256",
                  "checked_message_count", "bound_message_count",
                  "structural_findings", "fallback_findings", "binding_findings"):
        require(fluent.get(field) == actual.get(field),
                f"Fluent audit differs from current canonical source: {field}")
    require(fluent["checked_message_count"] > 0 and fluent["bound_message_count"] > 0,
            "Fluent audit did not inspect any messages")
    require(all(fluent[field] == [] for field in
                ("structural_findings", "fallback_findings", "binding_findings")),
            "Fluent audit contains unresolved findings")

    matrix = contract["visual_matrix"]
    baseline = contract["current_baseline"]
    required_cells = set(product(contract["good_bear_surfaces"], matrix["themes"],
                                 matrix["scales"], matrix["accessibility_states"]))
    required_shield = set(product(matrix["themes"], matrix["scales"],
                                  matrix["trust_panel_states"]))
    visual = transition.get("visual_evidence")
    require(isinstance(visual, list) and len(visual) == len(matrix["platforms"]),
            "reviewed transition lacks visual evidence for every platform")
    candidates, builds, observed = {}, {}, {}
    screenshot_paths = set()
    validated_pngs = set()
    for entry in visual:
        require(isinstance(entry, dict), "visual platform evidence must be an object")
        platform_name = entry.get("platform")
        require(platform_name in matrix["platforms"] and platform_name not in candidates,
                "visual evidence has unknown or duplicate platform")
        evidence_file(root, entry.get("candidate"), "visual candidate")
        candidates[platform_name] = entry["candidate"]["sha256"]
        build = load(evidence_file(root, entry.get("build"), "visual build"))
        builds[platform_name] = entry["build"]["sha256"]
        require(build.get("status") == "passed" and build.get("locale") == "ru" and
                build.get("firefox_baseline") == baseline and
                build.get("source_manifest_sha256") == actual["source_manifest_sha256"] and
                build.get("candidate_sha256") == candidates[platform_name],
                "visual build provenance differs from baseline, source or candidate")
        runtime = load(evidence_file(root, entry.get("runtime_report"), "visual runtime"))
        observed[platform_name] = entry["runtime_report"]["sha256"]
        require(runtime.get("status") == "passed" and runtime.get("runtime_verified") is True and
                runtime.get("errors") == [] and runtime.get("locale") == "ru" and
                runtime.get("platform") == platform_name and
                runtime.get("firefox_baseline") == baseline and
                runtime.get("candidate_sha256") == candidates[platform_name] and
                runtime.get("build_sha256") == builds[platform_name],
                "visual runtime is incomplete or bound to a different baseline/build/candidate")
        captures = runtime.get("captures")
        require(isinstance(captures, list) and captures, "visual runtime has no captures")
        cells, shields = set(), set()
        for capture in captures:
            require(isinstance(capture, dict) and capture.get("result") == "accepted" and
                    capture.get("locale") == "ru" and capture.get("viewport") == [1920, 1080],
                    "visual capture lacks successful Russian viewport review")
            cell = tuple(capture.get(key) for key in
                         ("surface", "theme", "scale", "accessibility_state"))
            require(cell in required_cells, "visual capture is outside the declared matrix")
            cells.add(cell)
            image = evidence_file(root, capture.get("png"), "visual PNG")
            require(image not in screenshot_paths, "visual capture reuses another matrix image")
            screenshot_paths.add(image)
            png_key = (capture["png"]["sha256"], cell[2])
            if png_key not in validated_pngs:
                verify_capture_png(image, cell[2])
                validated_pngs.add(png_key)
            if capture.get("trust_panel_state") is not None:
                shield_cell = (cell[1], cell[2], capture["trust_panel_state"])
                require(cell[0] in {"russian_pki_trust_indicator", "security_popup"} and
                        shield_cell in required_shield,
                        "shield state capture has the wrong surface/state")
                shields.add(shield_cell)
        require(cells == required_cells, "visual matrix surface/theme/scale/accessibility coverage is incomplete")
        require(shields == required_shield, "visual matrix native shield-state coverage is incomplete")

    manual = transition.get("manual_promotion")
    require(isinstance(manual, dict), "reviewed transition lacks manual promotion")
    require(isinstance(manual.get("maintainer"), str) and manual["maintainer"].strip(),
            "manual promotion lacks named maintainer")
    require(isinstance(manual.get("reviewed_at"), str), "manual promotion lacks an ISO timestamp")
    try:
        reviewed_at = datetime.fromisoformat(manual.get("reviewed_at", "").replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise WatchError("manual promotion lacks an ISO timestamp") from exc
    require(reviewed_at.tzinfo is not None, "manual promotion timestamp lacks timezone")
    require(manual.get("decision") == "promote" and manual.get("visual_result") == "accepted" and
            manual.get("unexplained_drift") == [] and manual.get("firefox_baseline") == baseline and
            manual.get("candidate_hash") == candidates and manual.get("build_hash") == builds and
            manual.get("observed_evidence") == observed and
            manual.get("fluent_audit_sha256") == fluent_ref["sha256"],
            "manual promotion is not bound to accepted baseline/artifact/Fluent evidence")


def verify(root: Path = ROOT, contract_path: Path = CONTRACT,
           source: Path | None = None) -> None:
    contract = load(contract_path)
    baseline = load(root / "config" / "firefox-baseline.json")
    require(contract.get("schema_version") == 1 and contract.get("task") == "GB100-M15-11",
            "invalid M15-11 contract identity")
    current = contract.get("current_baseline", {})
    require(current.get("version") == baseline.get("version") == "156.0",
            "UI watch baseline version drifted")
    require(current.get("revision") == baseline.get("vcs", {}).get("revision"),
            "UI watch baseline revision drifted")
    reference = contract.get("reference_baseline", {})
    require(reference == {
        "version": "155.0.1",
        "revision": "fb95137a04eb8fe1196cb12f26b100c1e060295c",
    }, "UI watch historical reference drifted")

    gate = contract.get("gate", {})
    require(gate == {
        "unknown_owner_delta": "block_rebase",
        "unknown_fluent_delta": "block_rebase",
        "unexplained_visual_drift": "block_rebase",
        "generated_baseline_update": "requires_named_manual_review",
        "unattended_promotion": "forbidden",
    }, "UI watch gate was weakened or is incomplete")
    require(set(contract.get("owner_scopes", [])) == {
        "browser_ui", "good_bear_branding", "fluent_l10n", "security_ui",
        "project_nova_or_equivalent_ui_architecture",
    }, "UI watch owner inventory drifted")
    require(set(contract.get("good_bear_surfaces", [])) == {
        "container_marker", "russian_pki_trust_indicator", "security_popup",
        "trust_change_interstitial", "request_body_interstitial", "settings",
        "assignment_management", "about", "updater_and_error_ux",
        "installer_and_launcher",
    }, "Good Bear visual surface inventory drifted")
    matrix = contract.get("visual_matrix", {})
    require(matrix.get("locale") == "ru", "visual gate must use Russian UI")
    require(set(matrix.get("themes", [])) == {"light", "dark"},
            "visual gate must cover light and dark themes")
    require(set(matrix.get("accessibility_states", [])) ==
            {"default", "hover", "keyboard_focus", "high_contrast"},
            "visual gate accessibility matrix is incomplete")
    require(set(matrix.get("trust_panel_states", [])) == {
        "secure", "scanning", "inactive", "warning", "breached",
        "first_visit_tracker_count", "repeat_visit_tracker_count",
    }, "visual gate shield state matrix is incomplete")
    require(matrix.get("scales") == [1.0, 1.25] and
            matrix.get("viewport") == "1920x1080",
            "visual gate geometry matrix drifted")
    require(set(matrix.get("platforms", [])) ==
            {"ubuntu-lts-amd64", "windows-x64"},
            "visual gate platform matrix is incomplete")

    transitions = contract.get("transitions")
    require(isinstance(transitions, list) and len(transitions) == 2,
            "exactly two upstream transitions are required")
    require([(item.get("from_train"), item.get("to_train")) for item in transitions] ==
            [("155", "156"), ("156", "157")], "upstream transition order drifted")
    require(transitions[0].get("status") in {"pinned_pending_review", "reviewed"},
            "selected Firefox 156 must retain its pinned review transition")
    require(transitions[1].get("status") == "blocked_by_previous_transition",
            "Firefox 157 cannot be reviewed while Firefox 156 is the selected baseline")
    for transition in transitions:
        status = transition.get("status")
        if status in {"pending_exact_upstream_release", "blocked_by_previous_transition"}:
            require(transition.get("target_pin") is None,
                    f"{transition.get('id')} has an unverified target pin")
            require(transition.get("promotion_allowed") is False,
                    f"{transition.get('id')} may not promote while pending")
            require(transition.get("manual_promotion") is None,
                    f"{transition.get('id')} cannot record promotion before evidence")
            continue
        require(status in {"pinned_pending_review", "reviewed"},
                f"unknown transition status: {status}")
        pin = transition.get("target_pin", {})
        for field in ("version", "revision", "release_artifact_url", "sha256",
                      "signature", "retrieved_at", "mozilla_release_provenance",
                      "mozilla_security_provenance"):
            require(isinstance(pin.get(field), str) and pin[field],
                    f"reviewed {transition.get('id')} lacks target pin {field}")
        if transition.get("to_train") == "156":
            expected_pin = {
                "version": baseline["version"],
                "revision": baseline["vcs"]["revision"],
                "release_artifact_url": baseline["source"]["archive_url"],
                "sha256": baseline["source"]["sha256"],
                "signature": baseline["source"]["detached_signature_url"],
                "mozilla_security_provenance": baseline["security_support"]["security_advisories_url"],
            }
            require(all(pin.get(key) == value for key, value in expected_pin.items()),
                    "UI watch target pin differs from verified Firefox baseline")
            audit = transition.get("ru_shield_source_audit", {})
            require(audit.get("from_revision") == reference["revision"] and
                    audit.get("to_revision") == pin["revision"],
                    "RU shield source audit revision drifted")
            require(set(audit.get("unchanged_owner_sha256", {})) == SHIELD_OWNERS,
                    "RU shield source owner inventory drifted")
            require(hashlib.sha256((root / BADGE_PATCH).read_bytes()).hexdigest() ==
                    audit.get("badge_patch_sha256"),
                    "RU badge patch changed without source audit")
            if source is not None:
                verify_ru_shield_source(source, audit, root)
        if status == "pinned_pending_review":
            require(transition.get("to_train") == "156",
                    "the next transition must remain blocked until 156 review")
            require(transition.get("promotion_allowed") is False,
                    f"{transition.get('id')} may not promote while pending review")
            require(transition.get("manual_promotion") is None,
                    f"{transition.get('id')} cannot record promotion before review")
            require(audit.get("status") == "source_checked_visual_pending" and
                    audit.get("visual_parity_proven") is False,
                    "source audit cannot claim rendered visual parity")
            require(bool(audit.get("remaining_evidence")),
                    "pending RU shield audit must declare missing evidence")
            continue
        require(len(transition.get("owner_dispositions", [])) > 0,
                f"reviewed {transition.get('id')} lacks owner dispositions")
        require(audit.get("status") == "source_and_visual_reviewed" and
                audit.get("visual_parity_proven") is True,
                "reviewed transition still has only a source audit")
        verify_reviewed_evidence(root, contract, transition, source)
        if source is None:
            from host_build_context import SOURCE
            verify_ru_shield_source(SOURCE, audit, root)
        require(transition.get("promotion_allowed") is True,
                f"{transition.get('id')} promotion flag differs from manual decision")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-source", action="store_true",
                        help="check inherited shield owners in the canonical worktree")
    parser.add_argument("--check-fluent", action="store_true",
                        help="audit Russian Fluent AST and registered UI bindings; unresolved findings fail")
    args = parser.parse_args()
    try:
        source = None
        if args.check_source:
            from host_build_context import SOURCE
            source = SOURCE
        verify(source=source)
        if args.check_fluent:
            from verify_m15_11_fluent_audit import audit as fluent_audit
            report = fluent_audit()
            print(json.dumps(report, ensure_ascii=False, indent=2))
            if report["status"] != "passed":
                return 1
    except (WatchError, OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("M15-11 upstream UI watch verified; Firefox 156 Russian visual review and promotion remain pending")
    if source is not None:
        print("Inherited shield SVG/CSS source checks passed; rendered parity is not established")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
