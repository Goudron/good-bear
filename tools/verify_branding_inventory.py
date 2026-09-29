#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Validate reviewed Good Bear public-branding provenance decisions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_SURFACES = {
    "application", "package", "about", "onboarding", "error", "update", "launcher", "installer"
}
CLASSIFICATIONS = {
    "product_mark", "neutral_ui", "legal_attribution", "technical_identifier",
    "third_party_material",
}
REPRESENTATIONS = {"string", "asset"}
COVERAGE_REPRESENTATIONS = {"strings": "string", "assets": "asset"}
PUBLIC_IDENTITIES = {"allowed", "preserve_attribution", "prohibited"}
RELEASE_STATUSES = {"allowed", "development_only", "not_applicable", "replacement_required"}
RELEASE_BLOCKING = {"development_only", "replacement_required"}


class InventoryError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InventoryError(message)


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryError(f"cannot load branding inventory {path}: {exc}") from exc
    require(isinstance(value, dict), "branding inventory must be a JSON object")
    return value


def validate(inventory: dict, root: Path = ROOT, release: bool = False) -> None:
    require(inventory.get("schema_version") == 1, "unsupported branding inventory schema")
    review = inventory.get("review")
    require(isinstance(review, dict), "review metadata is missing")
    for key in ("upstream_revision", "method", "decision_rule"):
        require(isinstance(review.get(key), str) and review[key], f"review.{key} is missing")

    entries = inventory.get("entries")
    require(isinstance(entries, list) and entries, "entries must be a non-empty list")
    by_id: dict[str, dict] = {}
    blockers: list[str] = []
    root_resolved = root.resolve()
    for entry in entries:
        require(isinstance(entry, dict), "every inventory entry must be an object")
        entry_id = entry.get("id")
        require(isinstance(entry_id, str) and entry_id, "inventory entry id is missing")
        require(entry_id not in by_id, f"duplicate inventory entry id: {entry_id}")
        by_id[entry_id] = entry
        require(entry.get("surface") in REQUIRED_SURFACES, f"{entry_id}: unknown surface")
        require(entry.get("representation") in REPRESENTATIONS,
                f"{entry_id}: representation must be string or asset")
        require(entry.get("classification") in CLASSIFICATIONS,
                f"{entry_id}: unknown classification")
        require(entry.get("public_identity") in PUBLIC_IDENTITIES,
                f"{entry_id}: unknown public identity disposition")
        require(entry.get("release_status") in RELEASE_STATUSES,
                f"{entry_id}: unknown release status")
        for key in ("decision", "review_basis"):
            require(isinstance(entry.get(key), str) and entry[key], f"{entry_id}: {key} is missing")
        paths = entry.get("paths")
        require(isinstance(paths, list), f"{entry_id}: paths must be a list")
        if paths:
            for relative in paths:
                require(isinstance(relative, str) and relative, f"{entry_id}: invalid path")
                candidate = (root / relative).resolve()
                require(candidate.is_relative_to(root_resolved), f"{entry_id}: path escapes repository")
                require(candidate.is_file(), f"{entry_id}: reviewed path is missing: {relative}")
        else:
            require(entry.get("representation") == "asset" and
                    isinstance(entry.get("absence_reason"), str) and entry["absence_reason"],
                    f"{entry_id}: an empty path list needs an asset absence_reason")
        if entry["public_identity"] == "prohibited":
            require(entry["release_status"] == "replacement_required",
                    f"{entry_id}: prohibited public identity must require replacement")
        if entry["classification"] == "legal_attribution":
            require(entry["public_identity"] == "preserve_attribution",
                    f"{entry_id}: legal attribution must be preserved, not treated as a product mark")
        if entry["release_status"] in RELEASE_BLOCKING:
            blockers.append(entry_id)

    coverage = inventory.get("coverage")
    require(isinstance(coverage, dict), "coverage map is missing")
    require(set(coverage) == REQUIRED_SURFACES,
            "coverage must contain exactly the required public surfaces")
    covered: set[str] = set()
    for surface, forms in coverage.items():
        require(isinstance(forms, dict), f"{surface}: coverage must be an object")
        require(set(forms) == set(COVERAGE_REPRESENTATIONS),
                f"{surface}: coverage must contain strings and assets")
        for coverage_form, entry_ids in forms.items():
            representation = COVERAGE_REPRESENTATIONS[coverage_form]
            require(isinstance(entry_ids, list) and entry_ids,
                    f"{surface}: {coverage_form} coverage is empty")
            for entry_id in entry_ids:
                require(entry_id in by_id, f"{surface}: unknown entry {entry_id}")
                entry = by_id[entry_id]
                require(entry["surface"] == surface and entry["representation"] == representation,
                        f"{surface}: {entry_id} does not match its coverage declaration")
                covered.add(entry_id)
    require(covered == set(by_id), "every entry must be assigned to one reviewed surface form")

    if release and blockers:
        raise InventoryError("release blocked by branding inventory: " + ", ".join(sorted(blockers)))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path,
                        default=ROOT / "config" / "branding-provenance-inventory.json")
    parser.add_argument("--release", action="store_true",
                        help="fail when a reviewed public identity still needs replacement")
    args = parser.parse_args()
    try:
        validate(load(args.config), release=args.release)
    except InventoryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Good Bear branding/provenance inventory verified", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
