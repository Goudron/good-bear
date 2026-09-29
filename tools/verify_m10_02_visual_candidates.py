#!/usr/bin/env python3
"""Validate the preview-only provenance and selection gate for GB100-M10-02."""

# SPDX-License-Identifier: MPL-2.0
# Copyright © 2026 Valery Ledovskoy <valery@ledovskoy.com>

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RECORD = ROOT / "config" / "m10-02-visual-candidates.json"
REQUIRED_COMPONENTS = (
    "primary_mark_direction",
    "monochrome_icon_direction",
    "welcome_onboarding_pose",
    "illustrative_style",
)
REQUIRED_CONSTRAINTS = (
    "bear_is_not_a_portrait_or_likeness",
    "no_reference_photographs",
    "no_firefox_or_mozilla_source_or_derived_art",
    "no_fox_flame_or_orbit_silhouette",
    "no_government_symbol_or_security_state_claim",
    "no_text_or_watermark",
)
SELECTED_CANDIDATE_ID = "workshop-beacon"
SELECTED_STATUS = "selected_for_m10_03_refinement"
M10_03_REFINEMENT = (
    "Remove the non-final circular enclosing device from the monochrome icon "
    "direction. Retain an independent bear-with-modern-glasses silhouette."
)


class CandidateError(ValueError):
    """A M10-02 candidate record breaks the explicit preview gate."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for block in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate(record: dict[str, Any], *, release: bool = False) -> None:
    if record.get("schema_version") != 1:
        raise CandidateError("unsupported candidate schema")
    if record.get("milestone") != "GB100-M10-02":
        raise CandidateError("wrong milestone record")

    selection_gate = record.get("selection_gate", {})
    if selection_gate.get("selected_candidate_id") != SELECTED_CANDIDATE_ID:
        raise CandidateError("M10-02 must record the approved Workshop Beacon selection")
    if selection_gate.get("selection_recorded") is not True:
        raise CandidateError("M10-02 selection record must confirm the maintainer selection")
    if selection_gate.get("maintainer_selection") != (
        "Valery Ledovskoy explicitly selected candidate 01, Workshop Beacon."
    ):
        raise CandidateError("M10-02 maintainer selection record is incomplete")
    if selection_gate.get("required_m10_03_refinement") != M10_03_REFINEMENT:
        raise CandidateError("M10-02 must preserve the required M10-03 icon refinement")
    if selection_gate.get("release_asset_injection_allowed") is not False:
        raise CandidateError("preview candidates must not permit asset injection")

    generation = record.get("generation", {})
    if generation.get("input_images") != []:
        raise CandidateError("candidate generation must not use unrecorded input images")
    if generation.get("public_photograph_references") != []:
        raise CandidateError("no public photograph reference is authorized for M10-02")
    if generation.get("exact_confirmed_valery_reference_images") is not False:
        raise CandidateError("no confirmed Valery reference image exists for M10-02")

    candidates = record.get("candidates")
    if not isinstance(candidates, list) or len(candidates) != 3:
        raise CandidateError("M10-02 requires exactly three candidates")
    ids = {candidate.get("id") for candidate in candidates}
    if len(ids) != 3 or None in ids:
        raise CandidateError("candidate IDs must be present and unique")

    distinct_directions: set[tuple[str, ...]] = set()
    selected_count = 0
    for candidate in candidates:
        if candidate.get("artifact_status") != "preview_only":
            raise CandidateError(f"{candidate.get('id')}: candidate is not preview-only")
        selection_status = candidate.get("selection_status")
        if candidate.get("id") == SELECTED_CANDIDATE_ID:
            if selection_status != SELECTED_STATUS:
                raise CandidateError("Workshop Beacon must be selected only for M10-03 refinement")
            selected_count += 1
        elif selection_status != "not_selected":
            raise CandidateError(f"{candidate.get('id')}: non-selected candidate has an invalid status")
        for component in REQUIRED_COMPONENTS:
            if not candidate.get(component):
                raise CandidateError(f"{candidate.get('id')}: missing {component}")
        constraints = candidate.get("constraints_review", {})
        if any(constraints.get(name) is not True for name in REQUIRED_CONSTRAINTS):
            raise CandidateError(f"{candidate.get('id')}: mandatory visual restriction is not confirmed")
        traits = tuple(candidate.get("distinguishing_traits", []))
        if len(traits) < 3 or traits in distinct_directions:
            raise CandidateError(f"{candidate.get('id')}: candidate is not distinctly described")
        distinct_directions.add(traits)

        artifact = ROOT / candidate.get("artifact_path", "")
        if not artifact.is_file() or artifact.suffix.lower() != ".png":
            raise CandidateError(f"{candidate.get('id')}: preview artifact is missing or not PNG")
        if _sha256(artifact) != candidate.get("sha256"):
            raise CandidateError(f"{candidate.get('id')}: preview artifact hash does not match provenance")

    if selected_count != 1:
        raise CandidateError("M10-02 must record exactly one selected candidate")

    if release:
        raise CandidateError("release blocked: M10-02 previews require explicit selection and M10-03 approved artwork")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, default=DEFAULT_RECORD)
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    try:
        record = json.loads(args.record.read_text(encoding="utf-8"))
        validate(record, release=args.release)
    except (CandidateError, OSError, json.JSONDecodeError) as error:
        print(f"M10-02 candidate record invalid: {error}")
        return 1
    print("M10-02 preview candidates are valid; release remains blocked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
