#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Read-only M15-10 gate. Static contracts never substitute for run evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from m15_remote_transport import (
    canonical_json, load_contract, manifest_for, plan_for, result_files, sha256_file, verify_pki_prepared,
    verify_prepared,
)
from verify_m13_03_decision_coverage import validate_contract as validate_decision_contract
from verify_m15_04_firefox_155_contract import (
    PRIOR_PROFILE, TARGET_VERSION, verify as verify_migration_contract,
)
import verify_m15_11_upstream_ui_watch as upstream_ui_watch
import verify_m15_12_hosted_service_boundary as hosted_service_boundary
from verify_m15_09_update_delivery import validate_contract as validate_delivery_contract


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "config/m15-10-verification-matrix.json"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
VERSION_PAIR = {"good_bear": "1.0", "firefox": TARGET_VERSION}
REQUIRED_RUNTIME = {
    "targeted_tests_156": {"upstream_positive", "upstream_negative", "good_bear_positive", "good_bear_negative"},
    "profile_migration_154_to_156": {"bookmarks", "passwords", "history", "container_assignments", "user_preferences", "trust_scope_unchanged", "container_state_unchanged"},
    "russian_pki_container": {"valid_scoped_chain", "outside_container_rejected", "fake_anchor_rejected", "isolation_preserved"},
    "decision_branches_156": {"all_positive", "all_negative"},
    "spellcheck_ui_ru_en": {"fresh_profile_enabled", "ru_misspelling_marked", "ru_correct_unmarked", "en_misspelling_marked", "en_correct_unmarked", "user_language_choice", "no_dictionary_download"},
    "ubuntu_package_ownership": {"clean_ubuntu_install", "dpkg_owns_browser", "dpkg_owns_desktop_entry", "update_preserves_dpkg_ownership", "no_unowned_browser_files"},
}
# M13-05/06 authorize unsigned distribution with no auto-update claim.
# Keep the signed-update suite declared and explicitly unaccepted for that mode.
SIGNED_UPDATE_CHECKS = {"signed_metadata", "signed_complete_mar", "allowed_update_applied", "wrong_product_rejected", "wrong_channel_rejected", "replay_rejected", "downgrade_rejected", "modified_mar_rejected", "wrong_firefox_base_rejected", "wrong_platform_rejected", "rollback_on_failure", "privacy_fields_only"}
UNSIGNED_CHECKS = {
    "unsigned_disclosure_visible", "asset_sha256_verified", "sbom_matches_asset",
    "provenance_matches_frozen_source", "russian_verification_instruction_present",
    "corresponding_source_available", "application_updater_disabled",
    "no_automatic_update_request", "modified_asset_rejected",
    "incorrect_checksum_rejected", "incomplete_release_manifest_rejected",
}
REQUIRED_RUNTIME["windows_unsigned_distribution"] = UNSIGNED_CHECKS
REQUIRED_RUNTIME["ubuntu_unsigned_distribution"] = UNSIGNED_CHECKS | {
    "version_pinned_download", "checksum_verified_before_privilege_escalation",
}
DISTRIBUTION_POLICY = {
    "mode": "unsigned_manual_install",
    "application_updater_enabled": False,
    "auto_update_claim_allowed": False,
    "deferred_signed_update": {
        "id": "windows_signed_mar_e2e",
        "status": "not_accepted_for_this_release_mode",
        "required_checks": sorted(SIGNED_UPDATE_CHECKS),
        "activation": "separate_approved_signed_release_with_complete_runtime_evidence",
    },
}
PLATFORMS = {"ubuntu-amd64": ".deb", "windows-x64": ".exe"}
WINDOWS_WORKSPACE_KIND = "disposable Windows Server 2022 workspace"


class GateError(RuntimeError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise GateError(message)


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GateError(f"cannot read {path}: {exc}") from exc
    require(isinstance(value, dict), f"{path}: expected JSON object")
    return value


def within(base: Path, relative: str) -> Path:
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute()
            and ".." not in Path(relative).parts, f"unsafe evidence path: {relative}")
    path = (base / relative).resolve()
    require(path.is_relative_to(base.resolve()), f"evidence path escapes root: {relative}")
    return path


def matrix_contract(root: Path = ROOT) -> dict:
    verify_migration_contract(root)
    matrix = read_json(root / "config/m15-10-verification-matrix.json")
    require(set(matrix) == {"schema_version", "task", "release_gates", "firefox_version",
                            "prior_profile_version", "version_pair", "materialization_marker",
                            "decision_contract", "transport_contract", "static_contracts_only",
                            "remote_artifacts", "runtime_evidence", "distribution_policy"},
            "M15-10 matrix has missing or unknown fields")
    require(matrix.get("schema_version") == 1 and matrix.get("task") == "GB100-M15-10",
            "invalid M15-10 matrix")
    require(matrix.get("release_gates") == ["M13", "M14", "public_release"],
            "release gate scope changed")
    require(matrix.get("firefox_version") == TARGET_VERSION and
            matrix.get("prior_profile_version") == PRIOR_PROFILE["version"] and
            matrix.get("version_pair") == VERSION_PAIR,
            "migration/version pair changed")
    require(matrix.get("static_contracts_only") ==
            [f"GB100-M15-{n:02d}" for n in range(4, 10)] + ["GB100-M15-09a"],
            "static contracts must be separate from runtime evidence")
    require(matrix.get("distribution_policy") == DISTRIBUTION_POLICY,
            "unsigned distribution policy or deferred signed-update scope changed")
    runtime = matrix.get("runtime_evidence")
    require(isinstance(runtime, dict) and set(runtime) == set(REQUIRED_RUNTIME) and
            all(isinstance(matrix["runtime_evidence"][key], list) and
                len(matrix["runtime_evidence"][key]) == len(required) and
                set(matrix["runtime_evidence"][key]) == required
                for key, required in REQUIRED_RUNTIME.items()),
            "runtime evidence matrix is incomplete or altered")
    remote = matrix.get("remote_artifacts")
    require(isinstance(remote, dict) and set(remote) == set(PLATFORMS) and
            all(isinstance(remote[platform], dict) and
                set(remote[platform]) == {"suffix", "provenance", "builder_fingerprint_sha256"} and
                remote[platform]["suffix"] == suffix and
                remote[platform]["provenance"] == "logs/provenance.json" and
                (remote[platform]["builder_fingerprint_sha256"] is None or
                 isinstance(remote[platform]["builder_fingerprint_sha256"], str) and
                 SHA256.fullmatch(remote[platform]["builder_fingerprint_sha256"]))
                for platform, suffix in PLATFORMS.items()),
            "both remote artifact types and builder fingerprint pins are mandatory")
    require(matrix.get("transport_contract") == "config/m15-01-remote-transport.json" and
            matrix.get("decision_contract") == "config/m13-03-decision-coverage-contract.json" and
            matrix.get("materialization_marker") ==
            "source/worktrees/firefox-156.0/.good-bear-materialization.json",
            "source and coverage bindings changed")
    baseline = read_json(root / "config/firefox-baseline.json")
    marker = read_json(root / matrix["materialization_marker"])
    require(baseline.get("version") == marker.get("version") == TARGET_VERSION and
            baseline.get("source", {}).get("sha256") == marker.get("source_sha256") and
            baseline.get("source", {}).get("sha512") == marker.get("source_sha512") and
            marker.get("baseline_config_sha256") == sha256_file(root / "config/firefox-baseline.json"),
            "Firefox 156 materialization marker differs from baseline")
    series = [line.strip() for line in (root / "patches/series").read_text(encoding="utf-8").splitlines()
              if line.strip() and not line.lstrip().startswith("#")]
    require(marker.get("patches") == [
        {"path": name, "sha256": sha256_file(root / "patches" / name)} for name in series
    ], "Firefox 156 materialization marker differs from the ordered patch inputs")
    require(load_contract(root / matrix["transport_contract"]), "invalid transport contract")
    return matrix


def verify_report(root: Path, evidence_dir: Path, item_id: str, required: set[str],
                  manifest_sha: str, artifact_hashes: dict[str, str], decision_ids: set[str]) -> None:
    index = read_json(evidence_dir / "evidence.json")
    records = index.get("runtime", {})
    require(isinstance(records, dict) and item_id in records, f"missing runtime evidence: {item_id}")
    record = records[item_id]
    require(isinstance(record, dict) and set(record) == {"report", "sha256"} and
            isinstance(record["sha256"], str) and SHA256.fullmatch(record["sha256"]),
            f"invalid evidence index: {item_id}")
    report_path = within(evidence_dir, record["report"])
    require(report_path.is_file() and sha256_file(report_path) == record["sha256"],
            f"report hash mismatch: {item_id}")
    report = read_json(report_path)
    require(report.get("task") == "GB100-M15-10" and report.get("id") == item_id and
            report.get("status") == "passed" and
            report.get("source_manifest_sha256") == manifest_sha and
            report.get("version_pair") == VERSION_PAIR,
            f"wrong identity/status/source manifest: {item_id}")
    platform = report.get("platform")
    require(platform in PLATFORMS and
            report.get("artifact_sha256") == artifact_hashes.get(platform),
            f"{item_id}: run is not bound to a returned platform artifact")
    require(isinstance(report.get("runner"), str) and report["runner"].strip() and
            isinstance(report.get("executed_at"), str) and report["executed_at"].strip() and
            isinstance(report.get("command"), list) and report["command"] and
            all(isinstance(arg, str) and arg for arg in report["command"]),
            f"missing execution provenance: {item_id}")
    checks = report.get("checks")
    require(isinstance(checks, dict) and set(checks) == required and
            all(value is True for value in checks.values()), f"incomplete checks: {item_id}")
    log = report.get("log")
    require(isinstance(log, dict) and set(log) == {"path", "sha256"} and
            isinstance(log["sha256"], str) and SHA256.fullmatch(log["sha256"]),
            f"missing run log: {item_id}")
    log_path = within(evidence_dir, log["path"])
    require(log_path.is_file() and log_path.stat().st_size > 0 and
            sha256_file(log_path) == log["sha256"], f"run log hash mismatch: {item_id}")
    if item_id == "decision_branches_156":
        require(set(report.get("positive_ids", [])) == decision_ids and
                set(report.get("negative_ids", [])) == decision_ids and
                len(report["positive_ids"]) == len(decision_ids) and
                len(report["negative_ids"]) == len(decision_ids),
                "not every declared decision branch ran positive and negative on 156")
    required_platform = ("windows-x64" if item_id == "windows_unsigned_distribution" else
                         "ubuntu-amd64" if item_id in {"ubuntu_package_ownership",
                                                       "ubuntu_unsigned_distribution"} else None)
    if required_platform:
        require(platform == required_platform, f"{item_id}: wrong execution platform")
    if item_id == "profile_migration_154_to_156":
        require(report.get("prior_profile_version") == PRIOR_PROFILE["version"] and
                isinstance(report.get("prior_candidate_sha256"), str) and
                SHA256.fullmatch(report["prior_candidate_sha256"]),
                "migration must identify the real Firefox-154-derived candidate")


def verify_remote(root: Path, evidence_dir: Path) -> tuple[str, dict[str, str]]:
    remote_matrix = matrix_contract(root)["remote_artifacts"]
    manifest = verify_prepared(evidence_dir)
    plan = read_json(evidence_dir / "transport-plan.json")
    manifest_sha = plan["source_manifest_sha256"]
    require(manifest.get("task") == "GB100-M15-01" and
            set(plan.get("platforms", {})) == set(PLATFORMS),
            "remote plan lacks both platforms")
    contract_path = root / "config/m15-01-remote-transport.json"
    contract = load_contract(contract_path)
    windows_builder = read_json(root / "config/m15-03-direct-cloud-windows-2022.json")["builder"]["name"]
    require(contract["remote_workspaces"]["windows-x64"]["kind"] == WINDOWS_WORKSPACE_KIND,
            "M15-01 Windows transport does not declare the approved Server 2022 workspace")
    local_manifest = manifest_for(root, contract_path, contract)
    require(manifest == local_manifest and
            hashlib.sha256(canonical_json(local_manifest)).hexdigest() == manifest_sha,
            "returned builders do not map to the current frozen local source manifest")
    require(plan == plan_for(contract, manifest_sha, plan["source_bundle_sha256"]),
            "remote plan differs from the current local transport contract")
    pki_manifest = verify_pki_prepared(
        root,
        evidence_dir,
        evidence_dir / "source-manifest.json",
        evidence_dir / "source-bundle.tar",
    )
    require(pki_manifest["source_manifest_sha256"] == manifest_sha and
            pki_manifest["source_bundle_sha256"] == plan["source_bundle_sha256"],
            "verified Russian PKI input is not bound to the returned source plan")
    hashes: dict[str, str] = {}
    for platform, suffix in PLATFORMS.items():
        returned = evidence_dir / "returned" / f"{platform}-{manifest_sha[:16]}"
        result = read_json(returned / "result.json")
        require(result.get("task") == "GB100-M15-01" and
                result.get("platform") == platform and result.get("status") == "succeeded" and
                result.get("source_manifest_sha256") == manifest_sha and
                result.get("source_bundle_sha256") == plan["source_bundle_sha256"],
                f"{platform}: result does not match the one local frozen source")
        result_files(returned, result)
        actual = {path.relative_to(returned).as_posix() for path in returned.rglob("*") if path.is_file()}
        declared = {"result.json", *(item["path"] for item in result["artifacts"] + result["logs"])}
        require(actual == declared and
                len(declared) == 1 + len(result["artifacts"]) + len(result["logs"]) and
                not any(path.is_symlink() for path in returned.rglob("*")),
                f"{platform}: returned files differ from declared result or contain links/duplicates")
        artifacts = [item for item in result["artifacts"] if item["path"].endswith(suffix)]
        require(len(artifacts) == 1, f"{platform}: exactly one {suffix} artifact is required")
        hashes[platform] = artifacts[0]["sha256"]
        provenance_rel = "logs/provenance.json"
        provenance_entry = [item for item in result["logs"] if item["path"] == provenance_rel]
        require(len(provenance_entry) == 1, f"{platform}: independent provenance report absent")
        provenance = read_json(returned / provenance_rel)
        require(provenance.get("platform") == platform and
                provenance.get("source_manifest_sha256") == manifest_sha and
                provenance.get("source_bundle_sha256") == plan["source_bundle_sha256"] and
                provenance.get("artifact_sha256") == hashes[platform] and
                provenance.get("version_pair") == VERSION_PAIR and
                provenance.get("build_invocation") == contract["remote_workspaces"][platform]["build_invocation"] and
                isinstance(provenance.get("builder_identity"), str) and
                provenance["builder_identity"].strip(),
                f"{platform}: provenance does not identify source, artifact, versions and builder")
        if platform == "windows-x64":
            require(provenance["builder_identity"] == windows_builder,
                    "Windows provenance names a builder other than the pinned Server 2022 host")
        pinned_fingerprint = remote_matrix[platform]["builder_fingerprint_sha256"]
        require(pinned_fingerprint is not None and
                provenance.get("builder_fingerprint_sha256") == pinned_fingerprint,
                f"{platform}: builder fingerprint is absent or differs from the frozen local pin")
    return manifest_sha, hashes


def verify_ui_watch_promotion(root: Path) -> None:
    """Require the selected upstream transition's verified manual UI approval."""
    contract_path = root / "config/m15-11-upstream-ui-watch.json"
    # A valid source-only watch is useful during rebase, but is insufficient for
    # release. Validate all existing pin/audit/manual conditions before reading
    # the promotion flag, so setting that flag alone cannot open this gate.
    upstream_ui_watch.verify(root=root, contract_path=contract_path)
    watch = upstream_ui_watch.load(contract_path)
    current_train = watch["current_baseline"]["version"].split(".", 1)[0]
    current = next((transition for transition in watch["transitions"]
                    if transition["to_train"] == current_train), None)
    require(current is not None, "current Firefox transition has no UI review record")
    require(current["status"] == "reviewed" and
            current.get("promotion_allowed") is True and
            isinstance(current.get("manual_promotion"), dict) and
            current["manual_promotion"].get("decision") == "promote",
            f"Firefox {TARGET_VERSION} Russian visual review and named manual promotion remain pending")


def hosted_service_release_blockers(root: Path = ROOT) -> list[str]:
    contract_path = root / "config/m15-12-hosted-service-boundary.json"
    try:
        hosted_service_boundary.verify(root=root, contract_path=contract_path)
        contract = hosted_service_boundary.load(contract_path)
        problems = []
        if contract.get("release_status") != "ready":
            problems.append("M15-12 hosted-service runtime and fresh-profile evidence remain pending")
        for entry in contract["security_services"]:
            if entry.get("supplier_status") == "unresolved_release_blocker":
                problems.append(f"M15-12 security supplier review remains pending: {entry['id']}")
        return problems
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        return [f"M15-12 hosted-service boundary blocks release: {exc}"]


def unsigned_distribution_blockers(root: Path = ROOT) -> list[str]:
    """Validate disabled delivery, without treating unsigned artifacts as verified."""
    problems: list[str] = []
    try:
        # This rejects invented ready/signing evidence and floating Ubuntu assets.
        validate_delivery_contract(read_json(root / "config/m15-09-update-delivery-contract.json"))
    except (RuntimeError, OSError, ValueError, TypeError, KeyError) as exc:
        problems.append(f"unsigned distribution delivery contract fails: {exc}")
    identity = read_json(root / "config/product-identity.json")
    updater = identity.get("services", {}).get("application_updater", {})
    if updater.get("enabled") is not False or updater.get("endpoints") != []:
        problems.append("unsigned distribution requires disabled native updater and no endpoints")
    signing = read_json(root / "config/m15-08-signing-public-manifest.json")
    if signing.get("updater_enabled") is not False:
        problems.append("unsigned distribution cannot enable the signing-manifest updater")
    return problems


def blockers(root: Path = ROOT, evidence_dir: Path | None = None) -> list[str]:
    matrix = matrix_contract(root)
    problems: list[str] = []
    problems.extend(hosted_service_release_blockers(root))
    try:
        verify_ui_watch_promotion(root)
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
        problems.append(f"M15-11 upstream UI watch blocks release: {exc}")
    decision = read_json(root / matrix["decision_contract"])
    if decision.get("firefox_version") != TARGET_VERSION:
        problems.append("decision coverage contract is not rebased to Firefox 156")
    decisions = decision.get("decision_surface", {}).get("decisions", [])
    decision_ids = {row.get("id") for row in decisions if isinstance(row, dict)}
    if not decision_ids or len(decision_ids) != len(decisions):
        problems.append("decision coverage IDs are missing or duplicated")
    try:
        validate_decision_contract(decision, root=root)
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as exc:
        problems.append(f"decision coverage declaration fails: {exc}")
    transport = load_contract(root / matrix["transport_contract"])
    if transport["remote_workspaces"]["windows-x64"]["kind"] != WINDOWS_WORKSPACE_KIND:
        problems.append("M15-01 Windows transport does not declare the approved Server 2022 workspace")
    for platform, details in matrix["remote_artifacts"].items():
        if details["builder_fingerprint_sha256"] is None:
            problems.append(f"{platform}: independently recorded builder fingerprint is not pinned")
    problems.extend(unsigned_distribution_blockers(root))
    if evidence_dir is None or not evidence_dir.is_dir():
        problems.append("missing prepared M15-01 source/PKI manifests, bundles and both returned remote artifacts")
        problems.extend(f"missing runtime evidence: {item}" for item in REQUIRED_RUNTIME)
        return problems
    try:
        manifest_sha, artifact_hashes = verify_remote(root, evidence_dir)
    except (GateError, OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        problems.append(f"remote artifact/provenance verification failed: {exc}")
        manifest_sha, artifact_hashes = "", {}
    for item, required in REQUIRED_RUNTIME.items():
        try:
            require(bool(manifest_sha), "remote source manifest is not verified")
            verify_report(root, evidence_dir, item, required, manifest_sha,
                          artifact_hashes, decision_ids)
        except (GateError, OSError, ValueError, KeyError, TypeError) as exc:
            problems.append(str(exc))
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only GB100-M15-10 release gate")
    parser.add_argument("--evidence-dir", type=Path, help="M15-01 prepared/returned evidence root")
    parser.add_argument("--contract-only", action="store_true", help="validate the matrix and 156 marker only")
    args = parser.parse_args()
    try:
        if args.contract_only:
            matrix_contract()
            print("M15-10 matrix and Firefox 156 marker valid; release gate NOT evaluated")
            return 0
        failures = blockers(evidence_dir=args.evidence_dir)
    except (GateError, OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        failures = [str(exc)]
    print(json.dumps({"task": "GB100-M15-10", "release_ready": not failures,
                      "blocked_gates": [] if not failures else ["M13", "M14", "public_release"],
                      "blockers": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
