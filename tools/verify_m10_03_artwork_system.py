#!/usr/bin/env python3
"""Verify the approved Good Bear M10-03 mascot artwork contract."""

from __future__ import annotations

import argparse
from functools import cache
import json
from pathlib import Path
import struct
import sys
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_build_context import SOURCE  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_STATES = {
    "neutral_welcome", "thinking_setup", "concerned_generic_error", "success",
    "devices_sync", "backup_restore", "empty_state", "import_setup", "gratitude",
    "first_run_animation", "first_run_static_frame",
}
REQUIRED_ICON_SIZES = {16, 32, 48, 64, 128}
FORBIDDEN_REPLACEMENT_TOKENS = {"firefox", "mozilla", "fox"}


class ArtworkError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ArtworkError(message)


def png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()[:24]
    require(data.startswith(b"\x89PNG\r\n\x1a\n"), f"{path}: expected PNG")
    return struct.unpack(">II", data[16:24])


def paeth(left: int, above: int, upper_left: int) -> int:
    prediction = left + above - upper_left
    distances = (abs(prediction - left), abs(prediction - above), abs(prediction - upper_left))
    return (left, above, upper_left)[distances.index(min(distances))]


@cache
def png_alpha_bounds(path: Path) -> tuple[int, int, int, int]:
    """Return the opaque-content bounds for an 8-bit non-interlaced RGBA PNG."""
    data = path.read_bytes()
    require(data.startswith(b"\x89PNG\r\n\x1a\n"), f"{path}: expected PNG")
    width = height = bit_depth = color_type = interlace = None
    compressed = bytearray()
    cursor = 8
    while cursor < len(data):
        length = struct.unpack(">I", data[cursor:cursor + 4])[0]
        chunk = data[cursor + 4:cursor + 8]
        payload = data[cursor + 8:cursor + 8 + length]
        cursor += length + 12
        if chunk == b"IHDR":
            width, height, bit_depth, color_type, _compression, _filter, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
        elif chunk == b"IDAT":
            compressed.extend(payload)
        elif chunk == b"IEND":
            break
    require((bit_depth, color_type, interlace) == (8, 6, 0),
            f"{path}: safe-zone verification requires 8-bit non-interlaced RGBA PNG")
    assert width is not None and height is not None
    raw = zlib.decompress(compressed)
    stride = width * 4
    expected_length = height * (stride + 1)
    require(len(raw) == expected_length, f"{path}: malformed RGBA scanlines")
    left = top = None
    right = bottom = 0
    previous = bytearray(stride)
    cursor = 0
    for y in range(height):
        filter_type = raw[cursor]
        cursor += 1
        encoded = raw[cursor:cursor + stride]
        cursor += stride
        scanline = bytearray(stride)
        for x, value in enumerate(encoded):
            prior = scanline[x - 4] if x >= 4 else 0
            above = previous[x]
            upper_left = previous[x - 4] if x >= 4 else 0
            if filter_type == 0:
                restored = value
            elif filter_type == 1:
                restored = (value + prior) & 0xFF
            elif filter_type == 2:
                restored = (value + above) & 0xFF
            elif filter_type == 3:
                restored = (value + ((prior + above) // 2)) & 0xFF
            elif filter_type == 4:
                restored = (value + paeth(prior, above, upper_left)) & 0xFF
            else:
                raise ArtworkError(f"{path}: unsupported PNG filter {filter_type}")
            scanline[x] = restored
        for x in range(width):
            if scanline[x * 4 + 3]:
                left = x if left is None else min(left, x)
                top = y if top is None else min(top, y)
                right = max(right, x + 1)
                bottom = max(bottom, y + 1)
        previous = scanline
    require(left is not None and top is not None, f"{path}: decorative asset is fully transparent")
    return left, top, right, bottom


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtworkError(f"cannot load artwork system: {exc}") from exc
    require(isinstance(value, dict), "artwork system must be an object")
    return value


def validate(record: dict, root: Path = ROOT) -> None:
    require(record.get("schema_version") == 1, "unsupported artwork-system schema")
    require(record.get("milestone") == "GB100-M10-03", "wrong milestone")
    require(record.get("selected_direction") == "workshop-beacon", "selected direction is not Workshop Beacon")
    require(record.get("asset_status") == "final_release_ready_artwork", "artwork is not final")
    rights = record.get("rights")
    require(isinstance(rights, dict), "rights record is missing")
    for key in ("copyright", "license", "creation_method", "final_rights_review_owner"):
        require(isinstance(rights.get(key), str) and rights[key], f"rights.{key} is missing")
    require(rights.get("input_images") == [], "unapproved reference imagery is not allowed")
    require(rights.get("likeness_or_portrait_claim") is False, "mascot must not claim likeness")
    require(rights.get("third_party_or_upstream_art_used") is False, "upstream artwork cannot be used")
    invariants = record.get("identity_invariants")
    require(isinstance(invariants, dict) and all(invariants.values()), "identity invariant is not satisfied")
    error_contract = record.get("error_illustration_contract")
    require(isinstance(error_contract, dict), "error illustration contract is missing")
    require(error_contract.get("role") == "decorative_product_identity_only",
            "error illustration must be decorative product identity only")
    error_assets = error_contract.get("assets")
    expected_error_assets = {
        "overlay/toolkit/themes/shared/illustrations/goodbear-no-connection.png",
        "overlay/toolkit/themes/shared/illustrations/goodbear-security-error.png",
    }
    require(isinstance(error_assets, dict) and set(error_assets) == expected_error_assets,
            "error illustration safe-zone assets are incomplete")
    for relative, safe_zone in error_assets.items():
        require(isinstance(safe_zone, dict), f"{relative}: missing safe-zone metadata")
        canvas = safe_zone.get("canvas_px")
        margin = safe_zone.get("minimum_transparent_margin_px")
        require(isinstance(canvas, list) and len(canvas) == 2 and all(isinstance(value, int) for value in canvas),
                f"{relative}: invalid canvas")
        require(isinstance(margin, int) and margin > 0, f"{relative}: invalid transparent margin")
        path = root / relative
        require(png_size(path) == tuple(canvas), f"{relative}: canvas differs from safe-zone contract")
        left, top, right, bottom = png_alpha_bounds(path)
        require(left >= margin and top >= margin and canvas[0] - right >= margin and canvas[1] - bottom >= margin,
                f"{relative}: decorative content violates the transparent safe zone")
    layout = error_contract.get("layout")
    require(isinstance(layout, dict), "error illustration layout contract is missing")
    require(layout.get("functional_ui_preserved") == [
        "title", "warning_icon", "body", "buttons", "certificate_details"
    ], "functional error UI contract drift")
    stylesheet = root / layout.get("stylesheet", "")
    require(stylesheet.is_file(), "error illustration stylesheet is missing")
    stylesheet_text = stylesheet.read_text(encoding="utf-8")
    for required_css in (
        "> .img-container", "flex: 0 0 auto", "pointer-events: none",
        layout.get("image_selector"), "object-fit: contain", "object-position: center",
        layout.get("security_max_size"), layout.get("network_max_size"),
    ):
        require(isinstance(required_css, str) and required_css in stylesheet_text,
                "error illustration safe layout contract drift")
    illustrations = (SOURCE / "toolkit/content/errors/net-error-illustrations.mjs").read_text(encoding="utf-8")
    require('className: "goodbear-error-illustration no-connection"' in illustrations,
            "network error illustration is not bound to the safe layout")
    require('className: "goodbear-error-illustration"' in illustrations,
            "certificate error illustration is not bound to the safe layout")
    master = root / record.get("master", "")
    require(master.is_file(), "primary master is missing")
    require(png_size(master)[0] >= 512, "primary master is too small")
    states = record.get("state_assets")
    require(isinstance(states, dict) and set(states) == REQUIRED_STATES, "state set is incomplete")
    for state, relative in states.items():
        path = root / relative
        require(path.is_file(), f"{state}: artwork is missing")
        if state == "first_run_animation":
            require(path.read_bytes().startswith((b"GIF87a", b"GIF89a")), "first-run asset is not an animated GIF")
        else:
            require(png_size(path)[0] >= 128, f"{state}: PNG is too small")
    icons = record.get("ubuntu_icon_sizes")
    require(isinstance(icons, dict) and {int(size) for size in icons} == REQUIRED_ICON_SIZES, "Ubuntu icon sizes are incomplete")
    for raw_size, relative in icons.items():
        size = int(raw_size)
        require(png_size(root / relative) == (size, size), f"icon {size}: wrong dimensions")
    replacements = record.get("surface_replacements")
    require(isinstance(replacements, list) and len(replacements) == 24, "audited replacement map is incomplete")
    upstream_paths: set[str] = set()
    for item in replacements:
        require(isinstance(item, dict), "replacement must be an object")
        upstream = item.get("upstream")
        replacement = item.get("replacement")
        require(isinstance(upstream, str) and upstream and upstream not in upstream_paths, "duplicate or missing upstream mapping")
        upstream_paths.add(upstream)
        require(isinstance(replacement, str) and (root / replacement).is_file(), f"{upstream}: replacement is missing")
        require(not any(token in Path(replacement).name.lower() for token in FORBIDDEN_REPLACEMENT_TOKENS), f"{upstream}: replacement name is not independent")
        require(item.get("state") in states, f"{upstream}: missing declared mascot state")

    trustpanel_replacements = {
        "browser/themes/shared/identity-block/trustpanel-graphic-warning.svg": "goodbear-generic-error.png",
        "browser/themes/shared/identity-block/trustpanel-graphic-enabled.svg": "goodbear-success.png",
        "browser/themes/shared/identity-block/trustpanel-graphic-disabled.svg": "goodbear-empty-state.png",
    }
    replacement_map = {item["upstream"]: item["replacement"] for item in replacements}
    for upstream, asset_name in trustpanel_replacements.items():
        require(replacement_map.get(upstream, "").endswith(asset_name),
                f"{upstream}: Good Bear trust-panel replacement is missing")

    trustpanel_css = SOURCE / "browser/themes/shared/controlcenter/panel.css"
    trustpanel_text = trustpanel_css.read_text(encoding="utf-8")
    for asset_name in trustpanel_replacements.values():
        require(f"chrome://activity-stream/content/data/content/assets/{asset_name}" in trustpanel_text,
                f"trust-panel does not reference approved {asset_name}")
    require("chrome://browser/content/controlcenter/assets/breach-alert-shield-"
            not in trustpanel_text,
            "Trust Panel Nova artwork still references an upstream Firefox asset")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=ROOT / "config" / "m10-03-artwork-system.json")
    args = parser.parse_args()
    try:
        validate(load(args.config))
    except ArtworkError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Good Bear M10-03 artwork system verified", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
