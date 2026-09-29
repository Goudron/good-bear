#!/usr/bin/env python3
"""Validate the Firefox 156 rebase; retain this entry point's historical name."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
TARGET_VERSION = "156.0"
PRIOR_PROFILE = {
    "version": "154.0",
    "revision": "032a9fc1ac0cc3209f7c142744ba2e40847c8086",
}


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"expected JSON object: {path}")
    return value


def verify(root: Path = ROOT) -> None:
    baseline = load(root / "config/firefox-baseline.json")
    identity = load(root / "config/product-identity.json")
    contract = load(root / "config/m15-04-firefox-155-migration-contract.json")
    require(contract.get("schema_version") == 1 and contract.get("task") == "GB100-M15-04",
            "invalid M15-04 migration contract")
    require(contract.get("from") == PRIOR_PROFILE,
            "the historical Firefox 154 profile migration source must remain pinned")
    require(contract.get("selected_at") == baseline.get("selected_at") == "2026-09-16",
            "migration selection date differs from the frozen baseline")
    target = contract.get("to", {})
    source = baseline.get("source", {})
    require(target.get("version") == baseline.get("version") == TARGET_VERSION,
            "contract and baseline must pin Firefox 156.0")
    require(target.get("release_tag") == baseline.get("vcs", {}).get("release_tag") ==
            "FIREFOX_156_0_RELEASE",
            "release tag differs from the frozen baseline")
    require(target.get("revision") == baseline.get("vcs", {}).get("revision") ==
            "3bf8f468258c2181f455e23d4ffcd6acb8f4cdb1",
            "revision differs from the frozen baseline")
    require(target.get("archive") == "source/firefox-156.0.source.tar.xz",
            "archive does not identify the selected Firefox release")
    for key in ("archive_path", "sha256", "sha512"):
        contract_key = "archive" if key == "archive_path" else key
        require(target.get(contract_key) == source.get(key), f"source {key} differs from baseline")
    for key, length in (("sha256", 64), ("sha512", 128)):
        require(isinstance(target.get(key), str) and
                re.fullmatch(rf"[0-9a-f]{{{length}}}", target[key]) is not None,
                f"source {key} is missing or malformed")

    pair = contract.get("version_pair", {})
    identity_pair = identity.get("version_pair", {})
    require(pair.get("good_bear") == identity.get("product", {}).get("version") == "1.0",
            "Good Bear version pair is not pinned")
    require(pair.get("firefox") == target.get("version") == identity_pair.get("firefox_base_version"),
            "Firefox version pair is not pinned")
    require(pair.get("canonical_about_ru") == identity_pair.get("canonical_about_ru") ==
            f"Good Bear 1.0 (Firefox {TARGET_VERSION})",
            "About version pair is inconsistent")
    require(set(pair.get("required_in", [])) ==
            {"candidate", "provenance", "sbom", "source_offer", "about", "package", "update"},
            "version-pair dissemination boundary is incomplete")

    series = [line.strip() for line in (root / "patches/series").read_text(encoding="utf-8").splitlines()
              if line.strip() and not line.lstrip().startswith("#")]
    dispositions = contract.get("patch_dispositions", [])
    declared = [entry.get("patch") for entry in dispositions]
    require(declared == series, "every ordered Good Bear patch needs exactly one ordered disposition")
    for entry in dispositions:
        require(isinstance(entry.get("owner"), str) and entry["owner"],
                f"missing upstream owner for {entry.get('patch')}")
        require(entry.get("disposition") == "targeted_rebase_required",
                f"unsafe disposition for {entry.get('patch')}")
    rules = contract.get("migration_rules", {})
    require(rules.get("force_apply") == "forbidden" and
            rules.get("unknown_upstream_change") == "block_migration" and
            rules.get("firefox_154_compatibility_shim") == "forbidden" and
            rules.get("security_contracts") == "must_be_reexecuted_in_m15_05",
            "M15-04 must fail closed on unsafe rebase behavior")


def main() -> int:
    try:
        verify()
    except (ContractError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("M15-04 Firefox 156 migration contract verified; runtime evidence NOT evaluated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
