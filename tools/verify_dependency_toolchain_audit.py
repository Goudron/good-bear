#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Validate the bounded direct dependency/toolchain audit for Good Bear."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDIT = ROOT / "config" / "dependency-toolchain-audit.json"
DEFAULT_BASELINE = ROOT / "config" / "firefox-baseline.json"
DEFAULT_TOOLCHAIN_LOCK = ROOT / "config" / "toolchain-lock.json"
ALLOWED_OWNERSHIP = {"good_bear_direct", "ubuntu_environment_pending", "upstream_owned"}
ALLOWED_STATES = {
    "pin",
    "floor",
    "floor_and_tested_ceiling",
    "untracked_host_requirement",
    "planned_requirement",
    "upstream_source_version",
}
ALLOWED_DISPOSITIONS = {
    "retain_current_pin",
    "adopt_candidate_after_compatibility_gate",
    "adopted_and_verified",
    "do_not_adopt_latest_candidate",
    "defer_exact_pin_to_ubuntu_environment",
    "retain_upstream_owned_version",
}
REQUIRED_CATEGORIES = {
    "runtime", "compiler", "rust", "node", "python", "build", "test", "packaging",
    "browser_driver", "release",
}


class AuditError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def load_json(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"cannot load {label} {path}: {exc}") from exc
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def https_url(value: object, label: str) -> None:
    require(isinstance(value, str) and urlparse(value).scheme == "https",
            f"{label} must be an HTTPS URL")


def nonempty(value: object, label: str) -> None:
    require(isinstance(value, str) and value.strip(), f"{label} must be non-empty")


def verify(audit: dict, baseline: dict, toolchain_lock: dict | None = None) -> None:
    if toolchain_lock is None:
        toolchain_lock = load_json(DEFAULT_TOOLCHAIN_LOCK, "toolchain lock")
    lock_components = toolchain_lock.get("components")
    require(isinstance(lock_components, list), "toolchain lock components must be a list")
    lock_archives = {
        item.get("id"): item.get("archive", {}).get("url")
        for item in lock_components if isinstance(item, dict)
    }
    require(audit.get("schema_version") == 1, "unsupported audit schema_version")
    nonempty(audit.get("audited_at"), "audited_at")
    audit_baseline = audit.get("baseline")
    require(isinstance(audit_baseline, dict), "baseline must be an object")
    require(audit_baseline.get("firefox_version") == baseline.get("version"),
            "audit Firefox version does not match the immutable baseline")
    require(audit_baseline.get("revision") == baseline.get("vcs", {}).get("revision"),
            "audit Firefox revision does not match the immutable baseline")
    require(audit_baseline.get("source") == "config/firefox-baseline.json",
            "audit must name the baseline source")

    scope = audit.get("scope")
    require(isinstance(scope, dict), "scope must be an object")
    require(scope.get("target") == "Ubuntu LTS amd64", "audit target must be Ubuntu LTS amd64")
    require(scope.get("release_locale") == "ru", "audit release locale must be ru")
    categories = scope.get("categories")
    require(isinstance(categories, list) and set(categories) == REQUIRED_CATEGORIES,
            "audit scope categories are incomplete or unexpected")
    nonempty(scope.get("boundary"), "scope boundary")

    components = audit.get("components")
    require(isinstance(components, list) and components, "components must be a non-empty list")
    ids: set[str] = set()
    observed_categories: set[str] = set()
    revision = baseline["vcs"]["revision"]
    for index, component in enumerate(components):
        prefix = f"components[{index}]"
        require(isinstance(component, dict), f"{prefix} must be an object")
        component_id = component.get("id")
        nonempty(component_id, f"{prefix}.id")
        require(component_id not in ids, f"duplicate component ID: {component_id}")
        ids.add(component_id)
        component_categories = component.get("categories")
        require(isinstance(component_categories, list) and component_categories,
                f"{component_id}.categories must be a non-empty list")
        require(set(component_categories).issubset(REQUIRED_CATEGORIES),
                f"{component_id}.categories contains an unsupported category")
        observed_categories.update(component_categories)
        require(component.get("ownership") in ALLOWED_OWNERSHIP,
                f"{component_id}.ownership is unsupported")

        current = component.get("current_pin_or_floor")
        require(isinstance(current, dict), f"{component_id}.current_pin_or_floor must be an object")
        require(current.get("state") in ALLOWED_STATES, f"{component_id}.current state is unsupported")
        for field in ("version", "owner", "revision"):
            nonempty(current.get(field), f"{component_id}.current.{field}")
        https_url(current.get("source_url"), f"{component_id}.current.source_url")
        if current.get("revision") == revision:
            is_revision_url = revision in current["source_url"]
            is_verified_release_archive = (
                component_id == "firefox-gecko-runtime" and
                current["source_url"] == baseline["source"]["archive_url"]
            )
            require(is_revision_url or is_verified_release_archive,
                    f"{component_id} claims the Firefox revision but source URL is not immutable")

        latest = component.get("latest_stable_candidate")
        require(isinstance(latest, dict), f"{component_id}.latest_stable_candidate must be an object")
        for field in ("version", "observed_at"):
            nonempty(latest.get(field), f"{component_id}.latest.{field}")
        https_url(latest.get("source_url"), f"{component_id}.latest.source_url")

        compatible = component.get("compatible_stable_candidate")
        if compatible is not None:
            require(isinstance(compatible, dict),
                    f"{component_id}.compatible_stable_candidate must be an object")
            for field in ("version", "observed_at"):
                nonempty(compatible.get(field), f"{component_id}.compatible.{field}")
            https_url(compatible.get("source_url"), f"{component_id}.compatible.source_url")

        license_info = component.get("license_and_provenance")
        require(isinstance(license_info, dict), f"{component_id}.license_and_provenance must be an object")
        for field in ("license", "impact"):
            nonempty(license_info.get(field), f"{component_id}.license.{field}")
        evidence = component.get("compatibility_and_supply_chain_evidence")
        require(isinstance(evidence, list) and len(evidence) >= 2 and
                all(isinstance(item, str) and item.strip() for item in evidence),
                f"{component_id} needs two non-empty compatibility/supply-chain evidence items")
        disposition = component.get("disposition")
        require(isinstance(disposition, dict), f"{component_id}.disposition must be an object")
        require(disposition.get("status") in ALLOWED_DISPOSITIONS,
                f"{component_id}.disposition.status is unsupported")
        for field in ("rationale", "next_task", "m1_05_action"):
            nonempty(disposition.get(field), f"{component_id}.disposition.{field}")
        require(disposition["next_task"] in {"GB100-M1-05", "GB100-M1-06"},
                f"{component_id} must have a concrete M1-05 or M1-06 action owner")
        if component["ownership"] == "upstream_owned":
            require(disposition["status"] == "retain_upstream_owned_version",
                    f"{component_id} is upstream-owned and must not be treated as a Good Bear direct pin")
        if disposition["status"] == "do_not_adopt_latest_candidate" and not disposition.get("exception_reason"):
            require(compatible is not None,
                    f"{component_id} rejects the latest candidate without a compatible candidate")
        if disposition["status"] == "adopted_and_verified":
            require(component_id in {"rust-and-cargo", "clang-llvm-lld", "node-and-npm", "cbindgen"},
                    f"{component_id} is not an M1-05 direct toolchain adoption")
            require(disposition.get("toolchain_lock") == "config/toolchain-lock.json",
                    f"{component_id} adoption must name the immutable toolchain lock")
            nonempty(disposition.get("verification"), f"{component_id}.disposition.verification")
            require(current.get("source_url") == lock_archives.get(component_id),
                    f"{component_id} adopted source must match the immutable toolchain lock")
        if disposition["status"] == "do_not_adopt_latest_candidate":
            for field in ("exception_owner", "review_on_or_before", "follow_up"):
                nonempty(disposition.get(field), f"{component_id}.disposition.{field}")
            if disposition.get("exception_reason"):
                nonempty(disposition.get("exception_evidence"),
                         f"{component_id}.disposition.exception_evidence")

    require(observed_categories == REQUIRED_CATEGORIES,
            "not every required dependency/toolchain category is represented")
    require("firefox-gecko-runtime" in ids, "runtime baseline audit entry is missing")
    require("geckodriver" in ids, "browser-driver audit entry is missing")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    args = parser.parse_args()
    try:
        verify(load_json(args.audit, "dependency/toolchain audit"),
               load_json(args.baseline, "Firefox baseline"),
               load_json(DEFAULT_TOOLCHAIN_LOCK, "toolchain lock"))
    except AuditError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Good Bear direct dependency/toolchain audit verified", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
