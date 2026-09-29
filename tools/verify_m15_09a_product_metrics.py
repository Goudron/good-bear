#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Verify the inactive browser-metrics and GitHub download-count boundary."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config/m15-09a-product-metrics.json"


class MetricsError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MetricsError(message)


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path}: expected JSON object")
    return value


def verify(contract_path: Path = CONTRACT, root: Path = ROOT) -> None:
    contract = read_json(contract_path)
    require(contract.get("schema_version") == 1 and
            contract.get("task") == "GB100-M15-09a" and
            contract.get("firefox_base") == "156.0",
            "invalid M15-09a contract identity")
    baseline = read_json(root / "config/firefox-baseline.json")
    require(contract["firefox_base"] == baseline.get("version"),
            "metrics contract differs from the pinned Firefox baseline")
    placeholder = contract.get("browser_placeholder", {})
    require(placeholder.get("status") == "inactive_not_configured",
            "browser metrics must remain explicitly inactive")
    pref = placeholder.get("preference", {})
    require(pref == {
        "name": "goodbear.telemetry.enabled",
        "fresh_profile_default": True,
        "durable_user_choice": True,
    }, "inactive placeholder preference contract drifted")
    ui = placeholder.get("ui", {})
    require(ui.get("status_text") == "inactive_not_configured_no_data_is_sent" and
            ui.get("must_not_claim_live_collection") is True,
            "placeholder UI must disclose that no data is sent")
    runtime = placeholder.get("runtime", {})
    require(runtime == {
        "client": "absent",
        "endpoint": None,
        "collector_ready": False,
        "transport_gate": False,
        "identifier": "absent",
        "queue": "absent",
        "serialization": "absent",
        "dns": "forbidden",
        "network": "forbidden",
        "retry": "absent",
        "fallback": "forbidden",
        "network_requests_regardless_of_preference": 0,
    }, "inactive placeholder acquired a client, identity, endpoint, queue, or network path")
    future = placeholder.get("future_collector", {})
    require(future == {
        "maintainer_selected_domain": "ledovskoy.com",
        "status": "not_approved_not_configured_not_an_endpoint",
        "requires_separate_task": True,
    }, "future collector hint became an endpoint or dependency")

    downloads = contract.get("github_release_downloads", {})
    require(downloads.get("repository") == "Goudron/good-bear" and
            downloads.get("source") == "GitHub Releases REST API asset.download_count" and
            downloads.get("collection_side") == "maintainer_only" and
            downloads.get("input_mode") == "offline_saved_api_response" and
            downloads.get("distribution_assets") == {
                "ubuntu-amd64": [".deb"], "windows-x64": [".exe"]},
            "GitHub distribution download source/classification drifted")
    require(downloads.get("interpretation") ==
            "distribution_download_events_not_people_or_active_installations",
            "download counts must not be presented as users or active installations")
    require(set(downloads.get("forbidden_labels", [])) == {
        "unique_users", "active_users", "active_installations", "DAU", "WAU", "MAU"},
        "forbidden dashboard interpretations are incomplete")
    required = {
        "repository", "observed_at", "source_api_url", "source_response_sha256",
        "release_tag", "release_id", "asset_id", "asset_name", "asset_updated_at",
        "download_count",
    }
    require(set(downloads.get("required_provenance", [])) == required,
            "download snapshot provenance is incomplete")
    require(contract.get("hosted_service_boundary") ==
            "config/m15-12-hosted-service-boundary.json" and
            contract.get("release_status") ==
            "browser_telemetry_inactive_download_snapshot_foundation_only",
            "M15-09a status/boundary binding drifted")

    boundary = read_json(root / contract["hosted_service_boundary"])
    telemetry = boundary.get("good_bear_usage_telemetry", {})
    require(telemetry.get("user_setting_default") is True and
            telemetry.get("transport_gate_default") is False and
            telemetry.get("endpoint_default") == "" and
            telemetry.get("runtime_status") ==
            "inactive_placeholder_no_client_transport_or_endpoint",
            "M15-12 does not enforce the inactive Good Bear placeholder")

    patch = (root / "patches/0037-good-bear-hosted-service-boundary.patch").read_text(
        encoding="utf-8")
    for fragment in (
        'pref("goodbear.telemetry.enabled", true);',
        'pref("goodbear.telemetry.transport.enabled", false);',
        'pref("goodbear.telemetry.endpoint", "");',
    ):
        require(fragment in patch, f"hosted-service patch is missing: {fragment}")
    lowered_patch = patch.lower()
    for forbidden in ("telemetry.ledovskoy.com", "fetch(", "xmlhttprequest",
                      "nsichannel", "uuidgenerator", "client_id", "clientid"):
        require(forbidden not in lowered_patch,
                f"inactive browser placeholder contains forbidden runtime path: {forbidden}")

    tool_path = root / downloads.get("snapshot_tool", "")
    require(tool_path.is_file(), "offline GitHub download snapshot tool is missing")
    tree = ast.parse(tool_path.read_text(encoding="utf-8"), filename=str(tool_path))
    imports = {alias.name.split(".")[0] for node in ast.walk(tree)
               if isinstance(node, ast.Import) for alias in node.names}
    imports |= {node.module.split(".")[0] for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module}
    require(not imports.intersection({"requests", "urllib", "http", "socket", "aiohttp"}),
            "download snapshot tool must remain offline-only")


def main() -> int:
    try:
        verify()
    except (MetricsError, OSError, ValueError, KeyError, SyntaxError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("M15-09a inactive product-metrics boundary verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
