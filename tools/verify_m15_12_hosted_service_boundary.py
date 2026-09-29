#!/usr/bin/env python3
"""Verify Good Bear's fail-closed Firefox hosted-service boundary."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_build_context import SOURCE


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "m15-12-hosted-service-boundary.json"


class BoundaryError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BoundaryError(message)


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BoundaryError(f"cannot read {path}: {exc}") from exc
    require(isinstance(value, dict), f"{path} must contain one JSON object")
    return value


EXPECTED_LOCAL_FEATURES = {
    "screenshots", "bookmarks", "passwords", "containers",
    "tracking_protection", "history",
}
EXPECTED_DISABLED = {
    "firefox_account_and_sync",
    "firefox_relay",
    "firefox_monitor",
    "pocket_and_discovery_stream",
    "sponsored_and_online_suggestions",
    "mozilla_vpn_and_ip_protection",
    "normandy_shield_and_nimbus",
    "mozilla_telemetry_glean_and_crash_upload",
    "mozilla_addon_and_dictionary_services",
}
EXPECTED_SECURITY = {
    "web_push",
    "automatic_doh_and_odoh",
    "network_geolocation",
    "translation_model_download",
    "form_autofill_model_download",
    "safe_browsing",
    "remote_settings_security_collections",
}
EXPECTED_OWNERS = {
    "browser/moz.configure",
    "browser/app/profile/firefox.js",
    "modules/libpref/init/all.js",
    "services/settings/Utils.sys.mjs",
    "services/settings/RemoteSettingsClient.sys.mjs",
    "security/manager/ssl/RemoteSecuritySettings.sys.mjs",
}
PRESERVED_SECURITY_PREFS = {
    "safe_browsing": {
        "browser.safebrowsing.phishing.enabled": True,
        "browser.safebrowsing.malware.enabled": True,
        "browser.safebrowsing.downloads.remote.enabled": True,
    },
    "remote_settings_security_collections": {
        "security.remote_settings.intermediates.enabled": True,
        "security.remote_settings.crlite_filters.enabled": True,
    },
}
PRESERVED_SECURITY_ENDPOINTS = {
    "browser.safebrowsing.downloads.remote.url", "services.settings.server",
    *(f"browser.safebrowsing.provider.{provider}.{operation}"
      for provider in ("google", "google4", "google5")
      for operation in ("updateURL", "gethashURL")),
}
PRESERVED_COLLECTIONS = {
    "security-state/onecrl", "security-state/intermediates", "security-state/cert-revocations",
}


def verify_native_security_collections(source: str) -> None:
    require('const SECURITY_STATE_BUCKET = "security-state";' in source and
            'const SECURITY_STATE_SIGNER = "onecrl.content-signature.mozilla.org";' in source,
            "native security collection bucket or signer changed and requires review")
    names = re.findall(
        r'RemoteSettings\("([^"]+)",\s*\{\s*bucketName:\s*SECURITY_STATE_BUCKET,\s*'
        r'signerName:\s*SECURITY_STATE_SIGNER,', source)
    require(len(names) == len(PRESERVED_COLLECTIONS) and
            {"security-state/" + name for name in names} == PRESERVED_COLLECTIONS,
            "declared security collections differ from the native signed clients")


def verify_patch_hunk_counts(text: str) -> None:
    """Reject trailing additions which git apply can ignore after a short count."""
    expected = actual = None
    for line in [*text.splitlines(), "diff --git end"]:
        if line.startswith(("@@ ", "diff --git ")):
            if expected is not None:
                require(actual == expected, "patch hunk counts leave unapplied or missing lines")
            expected = actual = None
        if line.startswith("@@ "):
            match = re.match(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@", line)
            require(match is not None, "invalid patch hunk header")
            expected = [int(value) if value is not None else 1 for value in match.groups()]
            actual = [0, 0]
        elif expected is not None and line.startswith((" ", "+", "-")):
            actual[0] += line[0] in " -"
            actual[1] += line[0] in " +"


def verify_preserved_security_defaults(patch_text: str) -> None:
    protected = PRESERVED_SECURITY_ENDPOINTS | {
        name for prefs in PRESERVED_SECURITY_PREFS.values() for name in prefs
    }
    for line in patch_text.splitlines():
        match = re.match(r'^\+\s*(?:pref|sticky_pref)\("([^"]+)",\s*(.*)\);', line)
        if match and match[1] in protected:
            require(False, f"security protection must preserve its upstream default: {match[1]}")


def by_id(entries: object, label: str, expected: set[str]) -> dict[str, dict]:
    require(isinstance(entries, list), f"{label} must be a list")
    result: dict[str, dict] = {}
    for entry in entries:
        require(isinstance(entry, dict), f"{label} entry must be an object")
        entry_id = entry.get("id")
        require(isinstance(entry_id, str) and entry_id, f"{label} entry lacks id")
        require(entry_id not in result, f"duplicate {label} id: {entry_id}")
        result[entry_id] = entry
    require(set(result) == expected,
            f"{label} inventory drift: expected {sorted(expected)}, got {sorted(result)}")
    return result


def pref_literal(name: str, value: object) -> str:
    if isinstance(value, bool):
        rendered = "true" if value else "false"
    elif isinstance(value, int):
        rendered = str(value)
    elif isinstance(value, str):
        rendered = json.dumps(value, ensure_ascii=False)
    else:
        raise BoundaryError(f"unsupported pref value for {name}: {value!r}")
    return f'+pref("{name}", {rendered});'


def verify(root: Path = ROOT, contract_path: Path = CONTRACT) -> None:
    contract = load(contract_path)
    baseline = load(root / "config" / "firefox-baseline.json")
    migration = load(root / "config" / "m15-04-firefox-155-migration-contract.json")

    require(contract.get("schema_version") == 1 and contract.get("task") == "GB100-M15-12",
            "invalid M15-12 contract identity")
    base = contract.get("firefox_base", {})
    require(base.get("version") == baseline.get("version") == "156.0",
            "hosted-service audit is not pinned to Firefox 156.0")
    require(base.get("revision") == baseline.get("vcs", {}).get("revision") ==
            "3bf8f468258c2181f455e23d4ffcd6acb8f4cdb1",
            "hosted-service audit revision differs from the frozen baseline")
    require(migration.get("to", {}).get("version") == base["version"] and
            migration.get("to", {}).get("revision") == base["revision"],
            "hosted-service audit differs from the selected migration target")
    require(contract.get("request_scope") ==
            "privileged_background_and_product_feature_requests_only",
            "hosted-service policy must not masquerade as a content-navigation filter")
    require(contract.get("content_navigation_policy") == "not_filtered_by_this_contract",
            "ordinary web content navigation must remain outside this boundary")

    defaults = contract.get("defaults", {})
    require(defaults.get("unknown_endpoint") == "deny_and_fail_verification",
            "unknown privileged endpoint must fail closed")
    require(defaults.get("unknown_remote_config_collection") ==
            "deny_and_fail_verification",
            "unknown Remote Settings collection must fail closed")
    require(defaults.get("endpoint_redirect") == "reclassify_and_revalidate",
            "redirects must not escape endpoint classification")
    require(set(contract.get("retained_local_features", [])) == EXPECTED_LOCAL_FEATURES,
            "retained local-feature set drifted")
    require(set(contract.get("audit_owners", [])) == EXPECTED_OWNERS,
            "Firefox hosted-service audit owner set drifted")
    audit = contract.get("rebase_audit", {})
    require(audit.get("from_version") == "155.0.1" and
            audit.get("from_revision") == "fb95137a04eb8fe1196cb12f26b100c1e060295c" and
            audit.get("to_version") == base["version"] and
            audit.get("to_revision") == base["revision"],
            "hosted-service owner audit is not bound to the reviewed 155-to-156 delta")
    require(audit.get("evidence_kind") ==
            "static_named_owner_diff_only_not_runtime_outbound_evidence",
            "source owner review is not runtime outbound evidence")
    owner_dispositions = audit.get("owner_dispositions")
    require(isinstance(owner_dispositions, dict) and set(owner_dispositions) == EXPECTED_OWNERS,
            "every hosted-service audit owner needs a rebase disposition")
    for owner, disposition in owner_dispositions.items():
        expected = ("preserve_upstream_security_behavior" if owner.startswith(("services/settings/", "security/manager/ssl/"))
                    else "preserve_upstream_with_good_bear_overrides")
        require(isinstance(disposition, dict) and disposition.get("disposition") == expected and
                isinstance(disposition.get("review"), str) and disposition["review"].strip(),
                f"missing or unsafe hosted-service owner disposition: {owner}")

    switches = contract.get("build_switches", {})
    for name in ("MOZ_SERVICES_HEALTHREPORT", "MOZ_SERVICES_SYNC", "MOZ_NORMANDY"):
        require(switches.get(name) is False, f"{name} must be disabled at build time")
    require(switches.get("telemetry_configure_option") is None and
            switches.get("telemetry_disable_mechanism") ==
            "goodbear_hosted_service_runtime_policy_after_firefox_155_option_removal",
            "Firefox 155 telemetry removal must retain the Good Bear runtime boundary")

    good_bear_telemetry = contract.get("good_bear_usage_telemetry", {})
    require(good_bear_telemetry.get("implementation") ==
            "separate_from_mozilla_telemetry_and_glean",
            "Good Bear telemetry must not reactivate Mozilla Telemetry/Glean")
    require(good_bear_telemetry.get("user_setting_pref") == "goodbear.telemetry.enabled" and
            good_bear_telemetry.get("user_setting_default") is True,
            "Good Bear telemetry user setting must default to enabled")
    require(good_bear_telemetry.get("transport_gate_pref") ==
            "goodbear.telemetry.transport.enabled" and
            good_bear_telemetry.get("transport_gate_default") is False,
            "unconfigured Good Bear telemetry transport must fail closed")
    require(good_bear_telemetry.get("endpoint_pref") == "goodbear.telemetry.endpoint" and
            good_bear_telemetry.get("endpoint_default") == "",
            "Good Bear telemetry must not invent a production endpoint")
    require(good_bear_telemetry.get("missing_endpoint_behavior") ==
            "no_dns_no_connect_no_queue_no_send",
            "missing telemetry endpoint must produce no network activity")
    require(good_bear_telemetry.get("redirect_policy") == "forbidden",
            "telemetry endpoint redirects must fail closed")
    require(good_bear_telemetry.get("disable_invariant") ==
            "user_setting_false_overrides_all_other_state",
            "user opt-out must have unconditional precedence")
    require(set(good_bear_telemetry.get("disable_actions", [])) == {
        "persist_user_setting_false", "retain_zero_runtime_state",
        "retain_zero_network_requests",
    }, "Good Bear inactive placeholder opt-out semantics are incomplete")
    require(set(good_bear_telemetry.get("required_endpoint_contract", [])) == {
        "maintainer_controlled_https_origin", "version_pinned_exact_url",
        "documented_retention_and_deletion_policy",
        "documented_authentication_rate_limit_and_abuse_policy",
        "versioned_allowlisted_event_schema", "no_cookies_or_browser_account_identity",
        "no_url_history_search_certificate_container_or_free_text_fields",
        "independent_runtime_no-request-test-when-disabled",
        "privacy_notice_and_user_setting_ui",
    }, "Good Bear telemetry endpoint/privacy contract is incomplete")
    require(good_bear_telemetry.get("runtime_status") ==
            "inactive_placeholder_no_client_transport_or_endpoint",
            "Good Bear telemetry must remain an inactive placeholder in M15")

    disabled = by_id(contract.get("disabled_services"), "disabled service", EXPECTED_DISABLED)
    security = by_id(contract.get("security_services"), "security service", EXPECTED_SECURITY)
    for service_id, name in (
        ("firefox_account_and_sync", "identity.fxaccounts.telemetry.clientInfoPing.enabled"),
        ("firefox_relay", "browser.promo.relay.enabled"),
    ):
        require(disabled[service_id].get("prefs", {}).get(name) is False,
                f"Firefox 156 hosted-service default must be explicitly disabled: {name}")
    autofill = security["form_autofill_model_download"]
    require(autofill.get("prefs") == {"extensions.formautofill.useml": False} and
            autofill.get("endpoint_prefs_cleared") == [] and
            autofill.get("failure_mode") ==
            "use_local_regex_autofill_without_model_download; local_address_and_card_autofill_unchanged",
            "ML autofill must not download an unpinned model or disable local autofill")
    all_entries = list(disabled.values()) + list(security.values())
    endpoint_prefs: set[str] = set()
    all_pref_fragments: set[str] = set()
    denied_collections: set[str] = set()
    for entry in disabled.values():
        require(entry.get("ui") in {"absent", "local_file_install_only"},
                f"{entry['id']} retains an unclassified public UI")
        require(entry.get("background_network") == "denied",
                f"{entry['id']} does not deny background network access")
    for entry in security.values():
        if entry["id"] in PRESERVED_SECURITY_PREFS:
            require(entry.get("default") == "retained_security_protection_pending_supplier_review" and
                    entry.get("supplier_status") == "unresolved_release_blocker" and
                    entry.get("prefs") == PRESERVED_SECURITY_PREFS[entry["id"]] and
                    entry.get("endpoint_prefs_cleared") == [] and
                    not entry.get("remote_collections_denied"),
                    f"{entry['id']} must retain security protection while supplier review blocks release")
        else:
            require(str(entry.get("default", "")).startswith("disabled_pending_"),
                    f"{entry['id']} silently inherits a security supplier")
        require(isinstance(entry.get("failure_mode"), str) and entry["failure_mode"],
                f"{entry['id']} has no explicit failure mode")
    for entry in all_entries:
        if entry["id"] in PRESERVED_SECURITY_PREFS:
            continue
        prefs = entry.get("prefs", {})
        require(isinstance(prefs, dict) and prefs,
                f"{entry['id']} must have an executable preference boundary")
        for name, value in prefs.items():
            fragment = pref_literal(name, value)
            require(fragment not in all_pref_fragments,
                    f"preference disposition appears twice: {name}")
            all_pref_fragments.add(fragment)
        cleared = entry.get("endpoint_prefs_cleared", [])
        require(isinstance(cleared, list), f"{entry['id']} endpoint list must be a list")
        for name in cleared:
            require(isinstance(name, str) and name, f"{entry['id']} has invalid endpoint pref")
            require(name not in endpoint_prefs, f"endpoint pref disposition appears twice: {name}")
            endpoint_prefs.add(name)
            all_pref_fragments.add(pref_literal(name, ""))
        for collection in entry.get("remote_collections_denied", []):
            require(isinstance(collection, str) and collection,
                    f"{entry['id']} has invalid Remote Settings collection")
            require(collection not in denied_collections,
                    f"Remote Settings collection appears twice: {collection}")
            denied_collections.add(collection)

    all_pref_fragments.update({
        pref_literal("goodbear.telemetry.enabled", True),
        pref_literal("goodbear.telemetry.transport.enabled", False),
        pref_literal("goodbear.telemetry.endpoint", ""),
    })

    require({"nimbus-desktop-experiments", "messaging-experiments", "message-groups", "cfr"}
            <= denied_collections, "experiment/messaging collection boundary is incomplete")
    require(not PRESERVED_COLLECTIONS.intersection(denied_collections) and
            set(security["remote_settings_security_collections"].get("remote_collections_retained", [])) ==
            PRESERVED_COLLECTIONS,
            "certificate security collections must remain protected")
    security_owner = root / SOURCE.relative_to(ROOT) / "security/manager/ssl/RemoteSecuritySettings.sys.mjs"
    verify_native_security_collections(security_owner.read_text(encoding="utf-8"))
    retained_endpoints = {name for service_id in PRESERVED_SECURITY_PREFS
                          for name in security[service_id].get("endpoint_prefs_retained", [])}
    require(retained_endpoints == PRESERVED_SECURITY_ENDPOINTS and
            not retained_endpoints.intersection(endpoint_prefs),
            "security supplier endpoints must be retained pending review")
    require(contract.get("release_status") ==
            "blocked_until_runtime_outbound_and_fresh_profile_ui_evidence",
            "static policy must not promote a release without runtime evidence")

    patch_name = contract.get("implementation_patch")
    require(patch_name == "0037-good-bear-hosted-service-boundary.patch",
            "unexpected hosted-service implementation patch")
    patch = (root / "patches" / patch_name).read_text(encoding="utf-8")
    verify_patch_hunk_counts(patch)
    series = [line.strip() for line in (root / "patches" / "series").read_text(
        encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    series_text = "\n".join(
        (root / "patches" / name).read_text(encoding="utf-8") for name in series
    )
    verify_preserved_security_defaults(series_text)
    for fragment in (
        '-imply_option("MOZ_SERVICES_HEALTHREPORT", True)',
        '+imply_option("MOZ_SERVICES_HEALTHREPORT", False)',
        '-imply_option("MOZ_SERVICES_SYNC", True)',
        '+imply_option("MOZ_SERVICES_SYNC", False)',
        '-imply_option("MOZ_NORMANDY", True)',
        '+imply_option("MOZ_NORMANDY", False)',
    ):
        require(fragment in patch, f"implementation patch is missing: {fragment}")
    for fragment in sorted(all_pref_fragments):
        require(fragment in series_text,
                f"ordered implementation series is missing: {fragment}")
    monitor_patch = (root / "patches/0040-good-bear-trust-panel-hosted-service-guard.patch").read_text(
        encoding="utf-8")
    verify_patch_hunk_counts(monitor_patch)
    require('+        "browser.contentblocking.report.monitor.enabled",' in monitor_patch and
            '+      !Services.prefs.getStringPref("services.settings.server", "")' in monitor_patch,
            "Monitor must be gated independently of the shared security-settings server")

    ui_patch_name = contract.get("ui_enforcement_patch")
    require(ui_patch_name == "0038-good-bear-remove-fxa-sync-ui.patch",
            "unexpected Firefox Account/Sync UI enforcement patch")
    require(ui_patch_name in series and series.index(patch_name) < series.index(ui_patch_name),
            "Firefox Account/Sync UI enforcement must follow the disabled-service defaults")
    ui_patch = (root / "patches" / ui_patch_name).read_text(encoding="utf-8")
    for fragment in (
        '<toolbaritem id="appMenu-fxa-status2"',
        '<hbox id="appMenu-fxa-sign-in-promo"',
        '<toolbarseparator id="appMenu-fxa-separator" class="proton-zap" hidden="true"/>',
        'hidden="true"',
    ):
        require(fragment in ui_patch,
                f"Firefox Account/Sync UI enforcement is missing: {fragment}")
    dispositions = {item.get("patch"): item for item in migration.get("patch_dispositions", [])}
    require(dispositions.get(patch_name, {}).get("disposition") == "targeted_rebase_required",
            "M15-04 does not force hosted-service re-audit on rebase")
    require(dispositions.get(ui_patch_name, {}).get("disposition") == "targeted_rebase_required",
            "M15-04 does not force Firefox Account/Sync UI re-audit on rebase")

    mozconfig = (root / "overlay" / "build" / "goodbear" / "mozconfig").read_text(
        encoding="utf-8")
    require("ac_add_options --disable-telemetry" not in mozconfig,
            "Firefox 155 no longer accepts the removed telemetry configure option")


def main() -> int:
    try:
        verify()
    except (BoundaryError, OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("M15-12 Firefox 156 hosted-service static boundary verified; runtime evidence NOT evaluated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
