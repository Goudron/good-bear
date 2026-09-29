#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from host_build_context import SOURCE

BASELINE = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))
VERSION = BASELINE["version"]
FIREFOX = SOURCE

ORIGIN_ATTRIBUTES_H = FIREFOX / "caps/OriginAttributes.h"
ORIGIN_ATTRIBUTES_CPP = FIREFOX / "caps/OriginAttributes.cpp"
BASE_PRINCIPAL = FIREFOX / "caps/BasePrincipal.cpp"
STORAGE_ATTRIBUTES = FIREFOX / "dom/quota/StorageOriginAttributes.h"
CONTEXTUAL_IDENTITIES = (
    FIREFOX / "toolkit/components/contextualidentity/ContextualIdentityService.sys.mjs"
)
DOCSHELL = FIREFOX / "docshell/base/nsDocShell.cpp"
DOCUMENT_CHANNEL_CHILD = FIREFOX / "netwerk/ipc/DocumentChannelChild.cpp"
DOCUMENT_CHANNEL_PARENT = FIREFOX / "netwerk/ipc/DocumentChannelParent.h"
DOCUMENT_LOAD_LISTENER = FIREFOX / "netwerk/ipc/DocumentLoadListener.cpp"
HTTP_BASE_CHANNEL = FIREFOX / "netwerk/protocol/http/HttpBaseChannel.cpp"
TAB_CONTEXT_MENU = (
    FIREFOX / "browser/components/tabbrowser/content/tab-context-menu.js"
)
TABBROWSER = FIREFOX / "browser/components/tabbrowser/Tabbrowser.sys.mjs"
SESSION_STORE = FIREFOX / "browser/components/sessionstore/SessionStore.sys.mjs"

CAPS_MANIFEST = FIREFOX / "caps/tests/unit/xpcshell.toml"
CONTEXT_MANIFEST = (
    FIREFOX / "browser/components/contextualidentity/test/browser/browser.toml"
)
SESSION_MANIFEST = FIREFOX / "browser/components/sessionstore/test/browser.toml"
REFERRER_MANIFEST = FIREFOX / "browser/base/content/test/referrer/browser.toml"


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


def javascript_method_body(source: str, signature: str) -> str:
    signature_start = source.index(signature)
    body_start = source.index(") {", signature_start) + 2
    depth = 0
    for index in range(body_start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[body_start : index + 1]
    raise AssertionError(f"unterminated JavaScript method: {signature}")


def assert_in_order(test: unittest.TestCase, source: str, *needles: str) -> None:
    positions = [source.index(needle) for needle in needles]
    test.assertEqual(positions, sorted(positions), needles)


class M202ContainerNavigationContractTest(unittest.TestCase):
    def test_targeted_owners_and_upstream_probes_are_pinned(self) -> None:
        for owner in (
            ORIGIN_ATTRIBUTES_H,
            ORIGIN_ATTRIBUTES_CPP,
            BASE_PRINCIPAL,
            STORAGE_ATTRIBUTES,
            CONTEXTUAL_IDENTITIES,
            DOCSHELL,
            DOCUMENT_CHANNEL_CHILD,
            DOCUMENT_CHANNEL_PARENT,
            DOCUMENT_LOAD_LISTENER,
            HTTP_BASE_CHANNEL,
            TAB_CONTEXT_MENU,
            TABBROWSER,
            SESSION_STORE,
        ):
            self.assertTrue(owner.is_file(), owner)

        expected_tests = {
            CAPS_MANIFEST: ('["test_origin.js"]',),
            CONTEXT_MANIFEST: (
                '["browser_reopenIn.js"]',
                '["browser_usercontext.js"]',
                '["browser_windowOpen.js"]',
            ),
            SESSION_MANIFEST: ('["browser_restoreTabContainer.js"]',),
            REFERRER_MANIFEST: (
                '["browser_referrer_open_link_in_container_tab.js"]',
            ),
        }
        for manifest, tests in expected_tests.items():
            source = read(manifest)
            for test_name in tests:
                self.assertIn(test_name, source)

    def test_builtin_identities_are_real_stable_user_contexts(self) -> None:
        source = read(CONTEXTUAL_IDENTITIES)
        defaults = source[source.index("_userIdentities:") : source.index("_systemIdentities:")]
        for icon, color, l10n_id in (
            ("fingerprint", "blue", "user-context-personal"),
            ("briefcase", "orange", "user-context-work"),
            ("dollar", "green", "user-context-banking"),
            ("cart", "pink", "user-context-shopping"),
        ):
            self.assertIn(f'icon: "{icon}"', defaults)
            self.assertIn(f'color: "{color}"', defaults)
            self.assertIn(f'l10nId: "{l10n_id}"', defaults)

        init = function_body(source, "init(path)")
        assert_in_order(
            self,
            init,
            "let userContextId = 1;",
            "identity.public = true;",
            "identity.userContextId = userContextId;",
            "userContextId++;",
            "this._defaultIdentities.push(identity);",
        )
        create = function_body(source, "create(name, icon, color, managedPurpose = \"\")")
        self.assertIn("let userContextId = ++this._lastUserContextId;", create)
        self.assertIn("userContextId,\n      public: true,", create)
        self.assertIn("if (managedPurpose) {", create)
        self.assertIn("identity.managedPurpose = managedPurpose;", create)

    def test_user_context_is_part_of_principal_and_storage_keys(self) -> None:
        header = read(ORIGIN_ATTRIBUTES_H)
        equals = function_body(header, "OriginAttributes& aOther,")
        self.assertIn("mUserContextId != aOther.mUserContextId", equals)
        self.assertIn("return false;", equals)
        self.assertIn("return EqualsIgnoring(aOther, STRIP_NONE);", header)
        self.assertIn("mUserContextId, mPrivateBrowsingId,", header)

        suffix = function_body(read(ORIGIN_ATTRIBUTES_CPP), "OriginAttributes::CreateSuffix(")
        assert_in_order(
            self,
            suffix,
            "mUserContextId != nsIScriptSecurityManager::DEFAULT_USER_CONTEXT_ID",
            'params.Set("userContextId"_ns, value);',
            "params.Serialize(value, true);",
        )

        principal_origin = function_body(read(BASE_PRINCIPAL), "BasePrincipal::GetOrigin(")
        self.assertIn("GetOriginSuffix(suffix)", principal_origin)
        self.assertIn("aOrigin.Append(suffix);", principal_origin)

        storage = read(STORAGE_ATTRIBUTES)
        self.assertIn("uint32_t UserContextId() const", storage)
        self.assertIn("return mOriginAttributes.mUserContextId;", storage)
        self.assertIn("mOriginAttributes.mUserContextId = aUserContextId;", storage)

    def test_top_level_context_identity_enters_load_info_and_real_channel(self) -> None:
        source = read(DOCSHELL)
        do_uri_load = function_body(source, "nsresult nsDocShell::DoURILoad(")
        assert_in_order(
            self,
            do_uri_load,
            "MakeRefPtr<LoadInfo>(",
            "DocumentChannel::CreateForDocument(",
        )
        self.assertIn("GetOriginAttributes(), loadFlags, cacheKey, rv,", do_uri_load)

        configure = function_body(
            source, "nsDocShell::CreateAndConfigureRealChannelForLoadState("
        )
        assert_in_order(
            self,
            configure,
            "attrs = aOriginAttributes;",
            "aRv = aLoadInfo->SetOriginAttributes(attrs);",
            "CreateRealChannelForDocument(",
        )
        create_real = function_body(source, "nsDocShell::CreateRealChannelForDocument(")
        self.assertIn("NS_NewChannelInternal(getter_AddRefs(channel), aURI, aLoadInfo,", create_real)

    def test_http_redirect_keeps_the_same_container_identity(self) -> None:
        redirect = function_body(
            read(HTTP_BASE_CHANNEL), "HttpBaseChannel::CloneLoadInfoForRedirect("
        )
        assert_in_order(
            self,
            redirect,
            "mLoadInfo.get())->Clone();",
            "OriginAttributes channelAttrs = newLoadInfo->GetOriginAttributes();",
            "attrs.mUserContextId = channelAttrs.mUserContextId;",
            "newLoadInfo->SetOriginAttributes(attrs);",
            "newLoadInfo->AppendRedirectHistoryEntry(this, isInternalRedirect);",
        )

    def test_document_navigation_has_one_parent_owned_cancel_path(self) -> None:
        child_cancel = function_body(
            read(DOCUMENT_CHANNEL_CHILD), "DocumentChannelChild::CancelWithReason("
        )
        assert_in_order(
            self,
            child_cancel,
            "mCanceled = true;",
            "SendCancel(aStatusCode, aReason);",
            "ShutdownListeners(aStatusCode);",
        )

        parent = read(DOCUMENT_CHANNEL_PARENT)
        recv_cancel = function_body(parent, "RecvCancel(")
        self.assertIn("mDocumentLoadListener->Cancel(aStatus, aReason);", recv_cancel)

        listener_cancel = function_body(
            read(DOCUMENT_LOAD_LISTENER), "DocumentLoadListener::Cancel("
        )
        assert_in_order(
            self,
            listener_cancel,
            "mChannel->CancelWithReason(aStatusCode, aReason);",
            "DisconnectListeners(aStatusCode, aStatusCode);",
        )

    def test_reopen_boundary_transfers_only_url_and_new_identity(self) -> None:
        reopen = function_body(read(TAB_CONTEXT_MENU), "reopenInContainer(event)")
        self.assertIn("tab.linkedBrowser.currentURI.spec", reopen)
        self.assertIn("userContextId,", reopen)
        self.assertIn("principalWithOA(", reopen)
        self.assertIn("triggeringPrincipal,", reopen)
        for forbidden in (
            "postData",
            "referrerInfo",
            "openerBrowser",
            "originStoragePrincipal",
            "sessionStorage",
        ):
            self.assertNotIn(forbidden, reopen)

        add_tab = javascript_method_body(read(TABBROWSER), "addTab(\n    uriString,")
        self.assertIn("postData,", add_tab)
        self.assertIn("referrerInfo,", add_tab)
        self.assertIn("openerBrowser,", add_tab)
        self.assertIn("if (openerBrowser?.browsingContext && !openWindowInfo)", add_tab)

    def test_window_open_and_session_restore_keep_real_user_context_id(self) -> None:
        create_tab = javascript_method_body(
            read(TABBROWSER), "\n  #createTab({\n    uriString,"
        )
        assert_in_order(
            self,
            create_tab,
            "if (userContextId == null && openerTab)",
            'userContextId = openerTab.getAttribute("usercontextid") || 0;',
            't.setAttribute("usercontextid", userContextId);',
        )

        session = read(SESSION_STORE)
        undo = function_body(session, "  undoCloseTab(aSource, aIndex, aTargetWindow)")
        self.assertIn("userContextId: state.userContextId,", undo)
        self.assertIn("this.#restoreTab(tab, state);", undo)
        restore = javascript_method_body(
            session, "\n  #restoreTab(tab, tabData, options = {})"
        )
        self.assertIn("userContextId: tabData.userContextId || 0,", restore)


if __name__ == "__main__":
    unittest.main()
