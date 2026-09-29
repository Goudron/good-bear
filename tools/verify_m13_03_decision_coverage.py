#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Validate the declared Good Bear decision-to-test coverage matrix.

This is a declaration-integrity gate, not a substitute for executing Firefox
tests.  It proves that every Good Bear patch is either assigned one positive
and one negative executable test selector, or explicitly excluded as a
mechanically limited non-decision patch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_build_context import SOURCE

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config/m13-03-decision-coverage-contract.json"
SERIES_PATH = ROOT / "patches/series"
SELECTOR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
EVIDENCE_SCOPE = "declaration_only_runtime_results_required_separately"


class DecisionCoverageError(RuntimeError):
    pass


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DecisionCoverageError(f"cannot load M13-03 contract: {exc}") from exc
    if not isinstance(document, dict):
        raise DecisionCoverageError("M13-03 contract must be an object")
    return document


def load_series(path: Path = SERIES_PATH) -> list[str]:
    try:
        entries = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except OSError as exc:
        raise DecisionCoverageError(f"cannot load Good Bear patch series: {exc}") from exc
    if not entries or len(entries) != len(set(entries)):
        raise DecisionCoverageError("Good Bear patch series is empty or contains duplicate entries")
    return entries


def source_root(root: Path) -> Path:
    return root / SOURCE.relative_to(ROOT)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def selector_locations(
    root: Path, owner: str, selector: str, firefox_version: str
) -> list[str]:
    escaped = re.escape(selector)
    if owner.endswith(".py"):
        pattern = re.compile(rf"^\s*(?:async\s+)?def\s+{escaped}\s*\(", re.MULTILINE)
    elif owner.endswith((".js", ".mjs")):
        pattern = re.compile(rf"\b(?:async\s+)?function\s+{escaped}\s*\(")
    elif owner.endswith(".cpp"):
        pattern = re.compile(rf"\bTEST(?:_F|_P)?\s*\(\s*\w+\s*,\s*{escaped}\s*\)")
    else:
        raise DecisionCoverageError(f"unsupported executable test owner: {owner}")
    owner_path = root / owner if owner.startswith("tests/") else source_root(root) / owner
    if owner_path.is_file() and pattern.search(owner_path.read_text(encoding="utf-8")):
        return [owner_path.relative_to(root).as_posix()]
    return []


def require_selector(
    root: Path, decision_id: str, polarity: str, evidence: Any, firefox_version: str
) -> dict[str, Any]:
    if not isinstance(evidence, dict) or set(evidence) != {"owner", "selector"}:
        raise DecisionCoverageError(f"{decision_id} {polarity} evidence must contain only owner and selector")
    owner = evidence["owner"]
    selector = evidence["selector"]
    if not isinstance(owner, str) or not owner or owner.startswith("/") or ".." in Path(owner).parts:
        raise DecisionCoverageError(f"{decision_id} {polarity} owner is not a project-relative path")
    if not isinstance(selector, str) or not SELECTOR_RE.fullmatch(selector):
        raise DecisionCoverageError(f"{decision_id} {polarity} selector is not an executable identifier")
    locations = selector_locations(root, owner, selector, firefox_version)
    if not locations:
        raise DecisionCoverageError(
            f"{decision_id} {polarity} selector is absent from declared owner: {owner}::{selector}"
        )
    return {"owner": owner, "selector": selector, "locations": locations}


def validate_contract(
    document: dict[str, Any], root: Path = ROOT, series: list[str] | None = None
) -> dict[str, Any]:
    if document.get("schema_version") != 1 or document.get("task") != "GB100-M13-03":
        raise DecisionCoverageError("unexpected M13-03 schema version or task")
    firefox_version = document.get("firefox_version")
    baseline_path = root / "config/firefox-baseline.json"
    baseline = load_contract(baseline_path)
    if (firefox_version != baseline.get("version") or firefox_version != "156.0" or
        document.get("firefox_revision") != baseline.get("vcs", {}).get("revision") or
        document.get("firefox_revision") != "3bf8f468258c2181f455e23d4ffcd6acb8f4cdb1"):
        raise DecisionCoverageError("M13-03 declaration differs from the pinned Firefox 156 baseline")
    if document.get("evidence_scope") != EVIDENCE_SCOPE:
        raise DecisionCoverageError("M13-03 declaration cannot claim runtime coverage evidence")
    surface = document.get("decision_surface")
    if not isinstance(surface, dict) or set(surface) != {
        "series", "declared_decision_count", "decisions"
    }:
        raise DecisionCoverageError("decision surface has missing or unknown fields")
    if surface["series"] != "patches/series":
        raise DecisionCoverageError("decision surface must be bound to patches/series")
    decisions = surface["decisions"]
    if not isinstance(decisions, list) or not decisions:
        raise DecisionCoverageError("decision surface must declare at least one decision")
    if surface["declared_decision_count"] != len(decisions):
        raise DecisionCoverageError("declared decision count does not match decision rows")

    series = load_series(root / surface["series"]) if series is None else series
    patch_files = {path.name for path in (root / "patches").glob("*.patch")}
    if set(series) != patch_files:
        raise DecisionCoverageError("patches/series does not enumerate exactly the Good Bear patch corpus")
    source = source_root(root)
    marker = load_contract(source / ".good-bear-materialization.json")
    if (marker.get("version") != firefox_version or
        marker.get("baseline_config_sha256") != sha256(baseline_path) or
        marker.get("source_sha256") != baseline.get("source", {}).get("sha256") or
        marker.get("source_sha512") != baseline.get("source", {}).get("sha512") or
        marker.get("patches") != [{"path": name, "sha256": sha256(root / "patches" / name)}
                                   for name in series]):
        raise DecisionCoverageError("M13-03 materialization differs from the pinned baseline and ordered patches")

    rows: list[dict[str, Any]] = []
    decision_ids: set[str] = set()
    decision_patches: set[str] = set()
    for index, decision in enumerate(decisions, start=1):
        if not isinstance(decision, dict) or set(decision) != {
            "id", "patch", "title", "positive", "negative", "evidence_kind"
        }:
            raise DecisionCoverageError(f"decision row {index} has missing or unknown fields")
        decision_id = decision["id"]
        expected_id = f"GB100-D{index:03d}"
        if decision_id != expected_id or decision_id in decision_ids:
            raise DecisionCoverageError(f"decision ids must be unique and contiguous; expected {expected_id}")
        decision_ids.add(decision_id)
        patch = decision["patch"]
        if not isinstance(patch, str) or patch not in series or patch in decision_patches:
            raise DecisionCoverageError(f"{decision_id} patch is missing from series or assigned twice")
        if not isinstance(decision["title"], str) or not decision["title"].strip():
            raise DecisionCoverageError(f"{decision_id} has no decision title")
        if not isinstance(decision["evidence_kind"], str) or not decision["evidence_kind"].strip():
            raise DecisionCoverageError(f"{decision_id} has no evidence kind")
        decision_patches.add(patch)
        rows.append(
            {
                "id": decision_id,
                "patch": patch,
                "title": decision["title"],
                "evidence_kind": decision["evidence_kind"],
                "positive": require_selector(
                    root, decision_id, "positive", decision["positive"], firefox_version
                ),
                "negative": require_selector(
                    root, decision_id, "negative", decision["negative"], firefox_version
                ),
            }
        )

    exclusions = document.get("explicit_nondecision_exclusions")
    if not isinstance(exclusions, list):
        raise DecisionCoverageError("non-decision exclusions must be a list")
    excluded_patches: set[str] = set()
    for exclusion in exclusions:
        if not isinstance(exclusion, dict) or set(exclusion) != {"patch", "reason"}:
            raise DecisionCoverageError("non-decision exclusion has missing or unknown fields")
        patch, reason = exclusion["patch"], exclusion["reason"]
        if (
            not isinstance(patch, str)
            or patch not in series
            or patch in decision_patches
            or patch in excluded_patches
            or not isinstance(reason, str)
            or not reason.strip()
        ):
            raise DecisionCoverageError("non-decision exclusion is invalid or overlaps a decision")
        excluded_patches.add(patch)

    if decision_patches | excluded_patches != set(series):
        raise DecisionCoverageError("every Good Bear patch must be a decision or explicit non-decision exclusion")
    native_owners = {row[polarity]["owner"] for row in rows for polarity in ("positive", "negative")
                     if not row[polarity]["owner"].startswith("tests/")}
    owner_hashes = document.get("native_test_owner_sha256")
    if not isinstance(owner_hashes, dict) or set(owner_hashes) != native_owners:
        raise DecisionCoverageError("every declared native test owner must have reviewed source bytes")
    for owner, digest in owner_hashes.items():
        if sha256(source / owner) != digest:
            raise DecisionCoverageError(f"native test owner changed after declaration review: {owner}")
    return {
        "task": document["task"],
        "firefox_version": firefox_version,
        "firefox_revision": document["firefox_revision"],
        "evidence_scope": EVIDENCE_SCOPE,
        "runtime_coverage_percent": None,
        "declared_decision_count": len(rows),
        "positive_covered": len(rows),
        "negative_covered": len(rows),
        "declaration_coverage_percent": 100,
        "explicit_nondecision_exclusion_count": len(excluded_patches),
        "decisions": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the validated matrix as JSON")
    args = parser.parse_args(argv)
    try:
        matrix = validate_contract(load_contract())
    except (DecisionCoverageError, OSError, ValueError) as exc:
        print(f"M13-03 decision coverage: FAIL: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(matrix, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        print(
            "M13-03 declared decision coverage: "
            f"{matrix['positive_covered']}/{matrix['declared_decision_count']} positive, "
            f"{matrix['negative_covered']}/{matrix['declared_decision_count']} negative; "
            f"{matrix['explicit_nondecision_exclusion_count']} explicit exclusion; runtime NOT measured."
        )
        for row in matrix["decisions"]:
            print(f"{row['id']} {row['patch']}: {row['positive']['selector']} / {row['negative']['selector']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
