#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))
VERSION = BASELINE["version"]
FIREFOX = ROOT / "source" / "worktrees" / f"firefox-{VERSION}"
CONTRACT_PATH = ROOT / "config/m2-03-state-partitioning-contract.json"

PASSWORD_PARENT = FIREFOX / "toolkit/components/passwordmgr/LoginManagerParent.sys.mjs"
PASSWORD_TEST = (
    FIREFOX
    / "toolkit/components/passwordmgr/test/unit/test_LoginManagerParent_getGeneratedPassword.js"
)
AUTOFILL_PARENT = FIREFOX / "toolkit/components/formautofill/FormAutofillParent.sys.mjs"
AUTOFILL_STORAGE = (
    FIREFOX / "toolkit/components/formautofill/default/FormAutofillStorage.sys.mjs"
)
HTTP_AUTH_PROVIDER = FIREFOX / "netwerk/protocol/http/nsHttpChannelAuthProvider.cpp"
HTTP_AUTH_CACHE = FIREFOX / "netwerk/protocol/http/nsHttpAuthCache.cpp"
CLIENT_AUTH_H = FIREFOX / "security/manager/ssl/nsClientAuthRemember.h"
CLIENT_AUTH_CPP = FIREFOX / "security/manager/ssl/nsClientAuthRemember.cpp"
SOCKET_CONTROL = FIREFOX / "security/manager/ssl/NSSSocketControl.cpp"
CONNECTION_INFO = FIREFOX / "netwerk/protocol/http/nsHttpConnectionInfo.cpp"
STATIC_PREFS = FIREFOX / "modules/libpref/init/StaticPrefList.yaml"
TLS_HANDSHAKER = FIREFOX / "netwerk/protocol/http/TlsHandshaker.cpp"
HTTP_TRANSACTION = FIREFOX / "netwerk/protocol/http/nsHttpTransaction.cpp"
SERVICE_WORKERS = FIREFOX / "dom/serviceworkers/ServiceWorkerManager.cpp"
CACHE_STORAGE = FIREFOX / "dom/cache/CacheStorage.cpp"
QUOTA_PRINCIPAL = FIREFOX / "dom/quota/PrincipalUtils.cpp"
HTTP_CACHE_KEYS = FIREFOX / "netwerk/cache2/CacheFileUtils.cpp"
OCSP_CACHE_TEST = FIREFOX / "security/manager/ssl/tests/gtest/OCSPCacheTest.cpp"
ORIGIN_ATTRIBUTES = FIREFOX / "caps/OriginAttributes.cpp"
PB_CONTAINER_TEST = (
    FIREFOX
    / "browser/components/contextualidentity/test/browser/browser_usercontextid_new_window.js"
)

PASSWORD_MANIFEST = FIREFOX / "toolkit/components/passwordmgr/test/unit/xpcshell.toml"
PSM_MANIFEST = FIREFOX / "security/manager/ssl/tests/unit/xpcshell.toml"
NETWORK_MANIFEST = FIREFOX / "netwerk/test/unit/xpcshell.toml"
CONTEXT_MANIFEST = (
    FIREFOX / "browser/components/contextualidentity/test/browser/browser.toml"
)
SERVICE_WORKER_MANIFEST = FIREFOX / "dom/serviceworkers/test/browser-common.toml"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    signature_start = source.index(signature)
    body_start = source.index("{", signature_start)
    depth = 0
    for index in range(body_start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[body_start : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


def state_map() -> dict[str, dict[str, object]]:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    return {state["id"]: state for state in contract["states"]}


class M203StatePartitioningContractTest(unittest.TestCase):
    def test_contract_is_complete_fail_closed_and_owned(self) -> None:
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(contract["task"], "GB100-M2-03")
        self.assertEqual(contract["firefox_version"], VERSION)
        self.assertEqual(
            set(contract["allowed_classifications"]),
            {"partitioned", "disabled", "guard_required"},
        )
        self.assertEqual(contract["unknown_policy"]["classification"], "blocked")

        states = state_map()
        self.assertEqual(
            set(states),
            {
                "password_and_autofill",
                "http_auth",
                "tls_client_auth",
                "connection_reuse",
                "zero_rtt",
                "service_workers",
                "caches",
                "private_browsing_plus_user_context",
            },
        )
        for state in states.values():
            self.assertIn(state["classification"], contract["allowed_classifications"])
            self.assertTrue(state["implementation_owner"])
            self.assertTrue(state["test_owner"])
            self.assertTrue(state["required_guard"])
            for relative_path in state["source_evidence"]:
                self.assertTrue((FIREFOX / relative_path).is_file(), relative_path)

        self.assertEqual(states["password_and_autofill"]["classification"], "guard_required")
        self.assertEqual(states["http_auth"]["classification"], "guard_required")
        self.assertEqual(states["zero_rtt"]["classification"], "guard_required")
        for state_id in (
            "tls_client_auth",
            "connection_reuse",
            "service_workers",
            "caches",
            "private_browsing_plus_user_context",
        ):
            self.assertEqual(states[state_id]["classification"], "partitioned")

    def test_password_and_form_autofill_are_profile_global(self) -> None:
        password_parent = read(PASSWORD_PARENT)
        search_start = password_parent.index("static async searchAndDedupeLogins(")
        search = password_parent[
            search_start : password_parent.index("\n  static ", search_start + 1)
        ]
        self.assertIn("origin: formOrigin,", search)
        self.assertNotIn("userContextId", search)
        self.assertNotIn("originAttributes", search)

        password_test = read(PASSWORD_TEST)
        self.assertIn(
            "The stored login uses the page origin, not the principal origin",
            password_test,
        )
        self.assertIn("^userContextId is only used as the in-memory cache key", password_test)

        autofill_parent = read(AUTOFILL_PARENT)
        form_origin = function_body(autofill_parent, "get formOrigin()")
        self.assertIn("documentPrincipal?.originNoSuffix", form_origin)
        records_start = autofill_parent.index("async getRecords(")
        records = autofill_parent[
            records_start : autofill_parent.index("\n  /*", records_start)
        ]
        self.assertIn("const records = await collection.getAll();", records)
        self.assertNotIn("userContextId", records)
        self.assertNotIn("privateBrowsingId", records)

        storage = read(AUTOFILL_STORAGE)
        self.assertIn('const PROFILE_JSON_FILE_NAME = "autofill-profiles.json";', storage)
        self.assertIn("export const formAutofillStorage = new FormAutofillStorage(", storage)
        self.assertNotIn("userContextId", storage)

    def test_http_origin_and_managed_russian_proxy_auth_are_partitioned(self) -> None:
        provider = read(HTTP_AUTH_PROVIDER)
        suffix_helper = function_body(provider, "static void GetOriginAttributesSuffix(")
        self.assertIn("GetOriginAttributesForNetworkState(aChan, oa);", suffix_helper)
        self.assertIn("oa.CreateSuffix(aSuffix);", suffix_helper)
        self.assertIn("ShouldIsolateGoodBearRussianPKIProxyAuth", provider)
        self.assertIn("GetAuthCacheOriginSuffix", provider)
        self.assertIn("PSM_COMPONENT_CONTRACTID", provider)
        self.assertIn("GetAuthCacheOriginSuffix(chan, aProxyAuth, suffix);", provider)
        self.assertIn("GetAuthCacheOriginSuffix(chan, proxyAuth, suffix);", provider)
        self.assertIn("GetAuthCacheOriginSuffix(chan, mProxyAuth, suffix);", provider)
        self.assertIn("GetAuthCacheOriginSuffix(chan, true, suffix);", provider)

        cache = read(HTTP_AUTH_CACHE)
        key = function_body(cache, "static inline void GetAuthKey(")
        self.assertIn("key.Append(originSuffix);", key)
        self.assertIn("key.Append(scheme);", key)
        self.assertIn("key.Append(host);", key)

    def test_tls_client_auth_decisions_use_full_origin_attributes(self) -> None:
        header = read(CLIENT_AUTH_H)
        self.assertIn("aOriginAttributes.CreateSuffix(mOriginAttributesSuffix);", header)
        source = read(CLIENT_AUTH_CPP)
        entry_key = function_body(source, "nsClientAuthRemember::GetEntryKey(")
        self.assertIn("aEntryKey.Append(mOriginAttributesSuffix);", entry_key)
        lookup = function_body(
            source, "nsClientAuthRememberService::HasRememberedDecision("
        )
        self.assertIn("new nsClientAuthRemember(aHostName, aOriginAttributes)", lookup)
        self.assertIn("nsIDataStorage::DataType::Private", lookup)
        self.assertIn("nsIDataStorage::DataType::Persistent", lookup)

    def test_connection_and_tls_session_reuse_use_full_origin_attributes(self) -> None:
        connection_key = function_body(read(CONNECTION_INFO), "void nsHttpConnectionInfo::BuildHashKey()")
        self.assertIn("mOriginAttributes.CreateSuffix(originAttributes);", connection_key)
        self.assertIn("mHashKey.Append(originAttributes);", connection_key)

        peer_id = function_body(read(SOCKET_CONTROL), "NSSSocketControl::GetPeerId(")
        self.assertIn("mOriginAttributes.CreateSuffix(suffix);", peer_id)
        self.assertIn("mPeerId.Append(suffix);", peer_id)

    def test_zero_rtt_is_enabled_and_can_send_request_bytes_before_classification(self) -> None:
        prefs = read(STATIC_PREFS)
        start = prefs.index("- name: security.tls.enable_0rtt_data")
        pref = prefs[start : prefs.index("\n\n", start)]
        self.assertIn("value: true", pref)

        init = function_body(read(TLS_HANDSHAKER), "nsresult TlsHandshaker::InitSSLParams(")
        self.assertIn("ssl->DisableEarlyData();", init)
        self.assertIn("Is0RttTcpExcluded(mConnInfo)", init)
        check = function_body(read(TLS_HANDSHAKER), "void TlsHandshaker::Check0RttEnabled(")
        self.assertIn("transaction->Do0RTT()", check)

        early = function_body(read(HTTP_TRANSACTION), "bool nsHttpTransaction::Do0RTT(")
        self.assertIn("mRequestHead->IsSafeMethod()", early)
        self.assertIn("m0RTTInProgress = true;", early)

    def test_service_worker_registration_key_contains_origin_attributes(self) -> None:
        source = read(SERVICE_WORKERS)
        principal_key = function_body(
            source, "nsresult ServiceWorkerManager::PrincipalToScopeKey("
        )
        self.assertIn("aPrincipal->GetOrigin(aKey)", principal_key)
        info_key = function_body(
            source, "nsresult ServiceWorkerManager::PrincipalInfoToScopeKey("
        )
        self.assertIn("content.attrs().CreateSuffix(suffix);", info_key)
        self.assertIn("aKey.Append(suffix);", info_key)

    def test_cache_api_http_cache_and_ocsp_cache_are_origin_partitioned(self) -> None:
        cache_storage = read(CACHE_STORAGE)
        self.assertIn("PrincipalToPrincipalInfo(aPrincipal, &principalInfo)", cache_storage)
        self.assertIn("GetEffectiveStoragePrincipalInfo()", cache_storage)

        quota = read(QUOTA_PRINCIPAL)
        principal_info = function_body(quota, "GetInfoFromValidatedPrincipalInfo(")
        self.assertIn("info.attrs().CreateSuffix(suffix);", principal_info)
        self.assertIn("nsCString origin = info.originNoSuffix() + suffix;", principal_info)

        http_cache = function_body(read(HTTP_CACHE_KEYS), "void AppendKeyPrefix(")
        self.assertIn("oa->CreateSuffix(suffix);", http_cache)
        self.assertIn("AppendTagWithValue(_retval, 'O', suffix);", http_cache)

        ocsp = read(OCSP_CACHE_TEST)
        oa_test = ocsp[ocsp.index("TEST_F(psm_OCSPCacheTest, TestOriginAttributes)") :]
        self.assertIn("attrs.mUserContextId = 1;", oa_test)
        self.assertIn("attrs.mPrivateBrowsingId = 1;", oa_test)
        self.assertIn("ASSERT_FALSE(cache.Get(certID, attrs, resultOut, timeOut));", oa_test)

    def test_private_browsing_and_user_context_ids_can_coexist(self) -> None:
        suffix = function_body(read(ORIGIN_ATTRIBUTES), "void OriginAttributes::CreateSuffix(")
        user_pos = suffix.index('params.Set("userContextId"_ns, value);')
        private_pos = suffix.index('params.Set("privateBrowsingId"_ns, value);')
        self.assertLess(user_pos, private_pos)

        browser_test = read(PB_CONTAINER_TEST)
        private_test = function_body(browser_test, "add_task(async function test_new_private_window()")
        self.assertIn("openWindowWithUserContextId(1, true)", private_test)
        self.assertIn("originAttributes.userContextId, 1", private_test)
        self.assertIn("originAttributes.privateBrowsingId,", private_test)
        self.assertIn('1,\n      "expected private context"', private_test)

    def test_selected_upstream_probes_are_manifested(self) -> None:
        expected = {
            PASSWORD_MANIFEST: (
                '["test_LoginManagerParent_getGeneratedPassword.js"]',
            ),
            PSM_MANIFEST: (
                '["test_client_auth_remember_service_read.js"]',
                '["test_session_resumption.js"]',
            ),
            NETWORK_MANIFEST: (
                '["test_cache_jar.js"]',
                '["test_retry_0rtt.js"]',
                '["test_separate_connections.js"]',
            ),
            CONTEXT_MANIFEST: ('["browser_usercontextid_new_window.js"]',),
            SERVICE_WORKER_MANIFEST: ('["browser_unregister_with_containers.js"]',),
        }
        for manifest, tests in expected.items():
            source = read(manifest)
            for test in tests:
                self.assertIn(test, source)


if __name__ == "__main__":
    unittest.main()
