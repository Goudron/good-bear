#!/usr/bin/env python3
"""Run live bidirectional GB100-M11-03 isolation checks in a fresh profile.

This is a host-side fallback for browser-chrome harness startup failures. It
uses a loopback origin and Marionette's chrome context to inspect actual
container OriginAttributes and runtime component behavior.  It never accepts a
certificate override and it does not log credential values.

The candidate also contains a native proxy authentication cache guard.  The
browser probe keeps the proxy route as a separately reported runtime item: a
normal end-user proxy prompt cannot safely be automated with synthetic
credentials, so only a local explicit-auth route is eligible for this probe.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import tarfile
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

from project_temp import temporary_directory
from host_build_context import FIREFOX_WORKTREE_NAME, ROOT, SOURCE
from verify_russian_release_archive import ArchiveError, verify as verify_archive


FIREFOX_VERSION = FIREFOX_WORKTREE_NAME.removeprefix("firefox-")
DEFAULT_ARCHIVE = (
    ROOT
    / "artifacts/development/m15-02-ubuntu-obj/dist/"
    f"goodbear-1.0+firefox{FIREFOX_VERSION}.ru.linux-x86_64.tar.xz"
)
TITLE_PREFIX = "GB100-M11-03:"
class ProbeError(RuntimeError):
    pass


class ProbeServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), ProbeHandler)
        # This deliberately records only the scenario label and whether the
        # browser supplied the expected test credential.  Test secrets must
        # never enter a log or an assertion failure.
        self.expected_auth: dict[str, str] = {}
        self.auth_attempts: list[tuple[str, bool]] = []

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"

    def expect(self, scope: str, authorization: str) -> None:
        self.expected_auth[scope] = authorization


class ProbeHandler(BaseHTTPRequestHandler):
    server: ProbeServer

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def _send(self, status: int, content_type: str, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - HTTP handler API
        parsed = urlparse(self.path)
        if parsed.path == "/sw.js":
            self._send(
                200,
                "application/javascript",
                "self.addEventListener('install', e => self.skipWaiting());"
                "self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));"
                "self.addEventListener('fetch', () => {});",
            )
            return
        if parsed.path == "/basic":
            header = self.headers.get("Authorization", "")
            scope = parse_qs(parsed.query).get("scope", [""])[0]
            authorized = bool(scope) and secrets.compare_digest(
                header, self.server.expected_auth.get(scope, "")
            )
            self.server.auth_attempts.append((scope, authorized))
            if not authorized:
                self.send_response(401)
                self.send_header(
                    "WWW-Authenticate", f'Basic realm="Good Bear M11-03 {scope}"'
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send(200, "text/plain", "authenticated")
            return
        if parsed.path != "/state":
            self._send(404, "text/plain", "not found")
            return

        query = parse_qs(parsed.query)
        mode = query.get("mode", [""])[0]
        token = query.get("token", [""])[0]
        if mode not in {"seed", "read"} or not token:
            self._send(400, "text/plain", "invalid probe request")
            return
        # The result is deliberately published only in the page title. The
        # harness reads aggregate state and never writes secrets to its log.
        self._send(
            200,
            "text/html; charset=utf-8",
            f"""<!doctype html><meta charset=utf-8><script>
const mode = {json.dumps(mode)};
const token = {json.dumps(token)};
const prefix = {json.dumps(TITLE_PREFIX)};
function openDB() {{
  return new Promise((resolve, reject) => {{
    const request = indexedDB.open('goodbear-m11-03', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('state');
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  }});
}}
async function idbGet(db) {{
  return new Promise((resolve, reject) => {{
    const request = db.transaction('state').objectStore('state').get('token');
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result || '');
  }});
}}
async function run() {{
  const db = await openDB();
  if (mode === 'seed') {{
    document.cookie = 'gb_m11_03_cookie=' + token + '; Path=/; SameSite=Lax; Max-Age=86400';
    localStorage.setItem('token', token);
    await new Promise((resolve, reject) => {{
      const tx = db.transaction('state', 'readwrite');
      tx.objectStore('state').put(token, 'token');
      tx.oncomplete = resolve; tx.onerror = () => reject(tx.error);
    }});
    const cache = await caches.open('goodbear-m11-03');
    await cache.put('/m11-03-cache', new Response(token));
    await navigator.serviceWorker.register('/sw.js');
    await navigator.serviceWorker.ready;
  }}
  const cache = await caches.open('goodbear-m11-03');
  const cached = await cache.match('/m11-03-cache');
  const result = {{
    cookie: document.cookie.includes('gb_m11_03_cookie=') ? document.cookie.split('gb_m11_03_cookie=')[1].split(';')[0] : '',
    localStorage: localStorage.getItem('token') || '',
    indexedDB: await idbGet(db),
    cache: cached ? await cached.text() : '',
    serviceWorker: (await navigator.serviceWorker.getRegistrations()).length > 0,
    controller: Boolean(navigator.serviceWorker.controller),
  }};
  document.title = prefix + JSON.stringify(result);
}}
run().catch(error => {{ document.title = prefix + JSON.stringify({{error: String(error)}}); }});
</script>""",
        )


class ProbeProxy(ThreadingHTTPServer):
    """Loopback HTTP proxy that issues genuine HTTP 407 Basic challenges."""

    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), ProbeProxyHandler)
        self.expected_auth: dict[str, str] = {}
        self.auth_attempts: list[tuple[str, bool]] = []

    def expect(self, scope: str, authorization: str) -> None:
        self.expected_auth[scope] = authorization


class ProbeProxyHandler(BaseHTTPRequestHandler):
    server: ProbeProxy

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def _scope(self) -> str:
        parsed = urlparse(self.path)
        query_scope = parse_qs(parsed.query).get("scope", [""])[0]
        if query_scope:
            return query_scope
        # Strict HTTPS mode upgrades the synthetic URL before it reaches the
        # proxy. CONNECT carries host:port rather than a request query, so the
        # opaque scenario label is carried in the test-only host instead.
        return self.path.split(":", 1)[0].split(".", 1)[0]

    def _handle_auth(self, *, connect: bool) -> None:
        scope = self._scope()
        # A manual proxy setting can make unrelated startup traffic reach the
        # loopback server. It is irrelevant unless it names one of our exact
        # test scenarios, and must never turn into an authentication success.
        if not scope or scope not in self.server.expected_auth:
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        header = self.headers.get("Proxy-Authorization", "")
        authorized = secrets.compare_digest(header, self.server.expected_auth[scope])
        self.server.auth_attempts.append((scope, authorized))
        if not authorized:
            self.send_response(407)
            self.send_header(
                "Proxy-Authenticate", f'Basic realm="Good Bear M11-03 proxy {scope}"'
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if connect:
            # The successful authentication result itself is the evidence.
            # Do not tunnel or contact a real host after it: the negative
            # direction must remain entirely local and secret-free.
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"proxy-authenticated"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - HTTP handler API
        self._handle_auth(connect=False)

    def do_CONNECT(self) -> None:  # noqa: N802 - HTTP handler API
        self._handle_auth(connect=True)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeError(message)


def extract(archive: Path, destination: Path) -> Path:
    try:
        with tarfile.open(archive, "r:xz") as bundle:
            bundle.extractall(destination, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise ProbeError(f"cannot extract archive: {exc}") from exc
    binary = destination / "goodbear" / "goodbear"
    require(binary.is_file(), f"Good Bear executable is absent: {binary}")
    return binary


def chrome(client: Any, script: str, args: list[Any] | None = None) -> Any:
    client.set_context("chrome")
    return client.execute_script(script, script_args=args or [], sandbox=None)


def chrome_async(client: Any, script: str, args: list[Any] | None = None) -> Any:
    client.set_context("chrome")
    result = client.execute_async_script(
        f"""
        const done = arguments[arguments.length - 1];
        (async () => {{ {script} }})().then(
          value => done({{ok: true, value}}),
          error => done({{ok: false, error: String(error), stack: error.stack}})
        );
        """,
        script_args=args or [],
        sandbox=None,
    )
    if not isinstance(result, dict) or not result.get("ok"):
        raise ProbeError(f"asynchronous chrome script failed: {result!r}")
    return result.get("value")


def wait_for_marionette(process: subprocess.Popen[str], profile: Path, log: Path) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ProbeError(f"Good Bear exited before Marionette was ready; see {log}")
        active_port = profile / "MarionetteActivePort"
        if active_port.is_file() and active_port.read_text(encoding="ascii").strip() == "2828":
            return
        time.sleep(0.2)
    raise ProbeError("Good Bear did not expose Marionette on 127.0.0.1:2828")


def open_state_tab(client: Any, url: str, user_context_id: int) -> dict[str, Any]:
    result = chrome_async(
        client,
        """
        const [url, userContextId, prefix] = arguments;
        const window = Services.wm.getMostRecentWindow("navigator:browser");
        const tab = window.gBrowser.addTab(url, {
          userContextId,
          triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
        });
        window.gBrowser.selectedTab = tab;
        const deadline = Date.now() + 30000;
        while (!tab.linkedBrowser.contentTitle.startsWith(prefix)) {
          if (Date.now() > deadline) {
            throw new Error(`state page did not finish: ${tab.linkedBrowser.currentURI.spec} title=${tab.linkedBrowser.contentTitle}`);
          }
          await new Promise(resolve => window.setTimeout(resolve, 100));
        }
        return {
          userContextId: tab.linkedBrowser.browsingContext.originAttributes.userContextId,
          title: tab.linkedBrowser.contentTitle,
        };
        """,
        [url, user_context_id, TITLE_PREFIX],
    )
    require(isinstance(result, dict), f"unexpected tab result: {result!r}")
    require(result.get("title", "").startswith(TITLE_PREFIX), "state title prefix is absent")
    try:
        state = json.loads(result["title"][len(TITLE_PREFIX) :])
    except (KeyError, json.JSONDecodeError) as exc:
        raise ProbeError(f"cannot decode state page result: {result!r}") from exc
    require(not state.get("error"), f"state page failed: {state!r}")
    state["userContextId"] = result.get("userContextId")
    return state


def wait_for_auth_requests(server: ProbeServer | ProbeProxy, count: int) -> None:
    deadline = time.monotonic() + 15
    while len(server.auth_attempts) < count:
        if time.monotonic() > deadline:
            raise ProbeError("authentication endpoint did not receive its expected request")
        time.sleep(0.1)


def basic_header(username: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")


def open_auth_tab(client: Any, url: str, user_context_id: int, key: str) -> None:
    """Start a real network request and retain its browser for prompt handling.

    We intentionally do not preload a credential, alter the auth cache, or
    inject a channel header. The server's 401/407 response is what creates the
    browser-owned tab-modal credential dialog.
    """
    chrome(
        client,
        """
        const [url, userContextId, key] = arguments;
        const window = Services.wm.getMostRecentWindow("navigator:browser");
        window.__goodBearM1103AuthTabs ||= new Map();
        const tab = window.gBrowser.addTab(url, {
          userContextId,
          triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
        });
        window.__goodBearM1103AuthTabs.set(key, tab);
        window.gBrowser.selectedTab = tab;
        """,
        [url, user_context_id, key],
    )


def handle_auth_prompt(client: Any, key: str, username: str | None, password: str | None) -> bool:
    """Accept or dismiss the actual native tab-modal HTTP authentication prompt.

    This is supported browser-chrome UI automation of the prompt produced by
    the loopback endpoint. It does not write the auth cache directly. Secret
    values are passed only to the transient dialog and never returned.
    """
    result = chrome_async(
        client,
        """
        const [key, username, password] = arguments;
        const window = Services.wm.getMostRecentWindow("navigator:browser");
        const tab = window.__goodBearM1103AuthTabs?.get(key);
        if (!tab) throw new Error(`unknown auth tab ${key}`);
        const deadline = Date.now() + 15000;
        let dialog;
        while (!(dialog = window.gBrowser.getTabDialogBox(tab.linkedBrowser)
          ._tabDialogManager?._topDialog)) {
          if (Date.now() > deadline) return {
            prompt: false,
            uri: tab.linkedBrowser.currentURI.spec,
            title: tab.linkedBrowser.contentTitle,
          };
          await new Promise(resolve => window.setTimeout(resolve, 100));
        }
        let doc, login, pass, common;
        while (true) {
          doc = dialog._frame.contentDocument;
          login = doc?.getElementById("loginTextbox");
          pass = doc?.getElementById("password1Textbox");
          common = doc?.getElementById("commonDialog");
          if (login && pass && common) break;
          if (Date.now() > deadline) break;
          await new Promise(resolve => window.setTimeout(resolve, 100));
        }
        if (!login || !pass || !common) {
          const ids = doc ? [...doc.querySelectorAll("[id]")].map(element => element.id).join(",") : "no-document";
          throw new Error(`network authentication prompt controls unavailable: ${ids}`);
        }
        const closed = new Promise(resolve => window.addEventListener(
          "DOMModalDialogClosed", resolve, {once: true}
        ));
        if (username === null || password === null) {
          common.cancelDialog();
        } else {
          login.value = username;
          pass.value = password;
          common.acceptDialog();
        }
        await closed;
        return {prompt: true};
        """,
        [key, username, password],
    )
    require(
        isinstance(result, dict) and result.get("prompt") is True,
        f"expected native HTTP authentication prompt was absent: {result!r}",
    )
    return True


def require_no_auth_prompt(client: Any, key: str) -> None:
    result = chrome_async(
        client,
        """
        const [key] = arguments;
        const window = Services.wm.getMostRecentWindow("navigator:browser");
        const tab = window.__goodBearM1103AuthTabs?.get(key);
        if (!tab) throw new Error(`unknown auth tab ${key}`);
        await new Promise(resolve => window.setTimeout(resolve, 500));
        return Boolean(window.gBrowser.getTabDialogBox(tab.linkedBrowser)
          ._tabDialogManager?._topDialog);
        """,
        [key],
    )
    require(result is False, "cached credential unexpectedly required a prompt")


def run_auth_cache_direction(
    client: Any,
    server: ProbeServer | ProbeProxy,
    *,
    prefix: str,
    url_template: str,
    source_context: int,
    destination_context: int,
) -> None:
    """Prove cache reuse in one context and prompt isolation in the other."""
    scope = f"{prefix}-{secrets.token_hex(8)}"
    username = f"m11-{secrets.token_hex(8)}"
    password = secrets.token_urlsafe(24)
    server.expect(scope, basic_header(username, password))
    scenario_url = url_template.format(scope=scope)

    start = len(server.auth_attempts)
    open_auth_tab(client, scenario_url, source_context, f"{scope}-seed")
    handle_auth_prompt(client, f"{scope}-seed", username, password)
    wait_for_auth_requests(server, start + 2)
    attempts = server.auth_attempts[start:]
    require(
        attempts[0] == (scope, False) and attempts[1] == (scope, True),
        f"native prompt did not produce exactly one successful source-context authentication for {prefix}",
    )

    start = len(server.auth_attempts)
    open_auth_tab(client, scenario_url, source_context, f"{scope}-same-context")
    wait_for_auth_requests(server, start + 1)
    require_no_auth_prompt(client, f"{scope}-same-context")
    require(
        server.auth_attempts[start:] == [(scope, True)],
        f"source-context authentication cache was not reused for {prefix}",
    )

    start = len(server.auth_attempts)
    open_auth_tab(client, scenario_url, destination_context, f"{scope}-other-context")
    handle_auth_prompt(client, f"{scope}-other-context", None, None)
    wait_for_auth_requests(server, start + 1)
    require(
        server.auth_attempts[start:] == [(scope, False)],
        f"{prefix} credential crossed the native Russian PKI container boundary",
    )


def configure_loopback_proxy(client: Any, proxy: ProbeProxy) -> None:
    """Use the local HTTP proxy only for the narrow proxy-auth evidence step."""
    chrome(
        client,
        """
        const [host, port] = arguments;
        Services.prefs.setIntPref("network.proxy.type", 1);
        Services.prefs.setCharPref("network.proxy.http", host);
        Services.prefs.setIntPref("network.proxy.http_port", port);
        // Set both schemes explicitly. Strict HTTPS mode upgrades the local
        // test request before proxy selection, and relying on the UI-only
        // share-proxy preference leaves the HTTPS transport unconfigured.
        Services.prefs.setCharPref("network.proxy.ssl", host);
        Services.prefs.setIntPref("network.proxy.ssl_port", port);
        Services.prefs.setBoolPref("network.proxy.share_proxy_settings", false);
        Services.prefs.setCharPref("network.proxy.no_proxies_on", "localhost, 127.0.0.1");
        """,
        ["127.0.0.1", proxy.server_port],
    )


def clear_loopback_proxy(client: Any) -> None:
    chrome(
        client,
        """
        Services.prefs.setIntPref("network.proxy.type", 0);
        for (const name of [
          "network.proxy.http", "network.proxy.http_port",
          "network.proxy.ssl", "network.proxy.ssl_port",
          "network.proxy.share_proxy_settings", "network.proxy.no_proxies_on"
        ]) Services.prefs.clearUserPref(name);
        """,
    )


def credential_state(client: Any, origin: str, ordinary: int, managed: int) -> dict[str, Any]:
    result = chrome_async(
        client,
        """
        const [origin, ordinaryId, managedId] = arguments;
        const window = Services.wm.getMostRecentWindow("navigator:browser");
        const findBrowser = userContextId => [...window.gBrowser.tabs].find(tab =>
          tab.linkedBrowser.currentURI.spec.startsWith(origin) &&
          tab.linkedBrowser.browsingContext.originAttributes.userContextId === userContextId
        )?.linkedBrowser;
        const ordinaryBrowser = findBrowser(ordinaryId);
        const managedBrowser = findBrowser(managedId);
        if (!ordinaryBrowser || !managedBrowser) throw new Error("state tabs unavailable for actor checks");
        const login = Cc["@mozilla.org/login-manager/loginInfo;1"].createInstance(Ci.nsILoginInfo);
        login.init(origin, origin, null, "ordinary-user", "ordinary-secret", "username", "password");
        await Services.logins.addLoginAsync(login);
        const queryLogins = async browser => browser.browsingContext.currentWindowGlobal
          .getActor("LoginManager")
          .receiveMessage({name: "PasswordManager:findLogins", data: {actionOrigin: origin, options: {}}});
        const ordinaryLogins = await queryLogins(ordinaryBrowser);
        const managedLogins = await queryLogins(managedBrowser);

        const { formAutofillStorage } = ChromeUtils.importESModule(
          "resource://autofill/FormAutofillStorage.sys.mjs"
        );
        await formAutofillStorage.initialize();
        await formAutofillStorage.addresses.add({
          "given-name": "Ordinary", "family-name": "Only", "street-address": "1 Example Street", "country": "US"
        });
        const queryRecords = async browser => browser.browsingContext.currentWindowGlobal
          .getActor("FormAutofill")
          // Do not request a field-filtered UI suggestion here: its country
          // availability is locale-dependent.  The isolation assertion is
          // about the profile-global records returned by the actor.
          .receiveMessage({name: "FormAutofill:GetRecords", data: {searchString: "", collectionName: "addresses", fieldName: null}});
        const ordinaryRecords = await queryRecords(ordinaryBrowser);
        const managedRecords = await queryRecords(managedBrowser);
        const beforeManagedWrite = (await formAutofillStorage.addresses.getAll()).length;
        await managedBrowser.browsingContext.currentWindowGlobal.getActor("FormAutofill").receiveMessage({
          name: "FormAutofill:SaveAddress", data: {address: {"given-name": "Must", "family-name": "NotSave", "street-address": "2 Example Street", "country": "US"}}
        });
        const afterManagedWrite = (await formAutofillStorage.addresses.getAll()).length;

        const clientAuthRememberService = Cc[
          "@mozilla.org/security/clientAuthRememberService;1"
        ].getService(Ci.nsIClientAuthRememberService);
        clientAuthRememberService.clearRememberedDecisions();
        clientAuthRememberService.rememberDecisionScriptable(
          "m11-03.invalid", {userContextId: ordinaryId}, null, 1
        );
        const ordinaryDecision = clientAuthRememberService.hasRememberedDecisionScriptable(
          "m11-03.invalid", {userContextId: ordinaryId}, {}
        );
        const managedDecisionBefore = clientAuthRememberService.hasRememberedDecisionScriptable(
          "m11-03.invalid", {userContextId: managedId}, {}
        );
        clientAuthRememberService.rememberDecisionScriptable(
          "m11-03.invalid", {userContextId: managedId}, null, 1
        );
        const ordinaryDecisionAfter = clientAuthRememberService.hasRememberedDecisionScriptable(
          "m11-03.invalid", {userContextId: ordinaryId}, {}
        );
        const managedDecision = clientAuthRememberService.hasRememberedDecisionScriptable(
          "m11-03.invalid", {userContextId: managedId}, {}
        );
        return {
          ordinaryLogins: ordinaryLogins?.logins?.length || 0,
          managedLogins: managedLogins?.logins?.length || 0,
          ordinaryRecords: ordinaryRecords?.records?.length || 0,
          managedRecords: managedRecords?.records?.length || 0,
          beforeManagedWrite, afterManagedWrite,
          ordinaryDecision, managedDecisionBefore, ordinaryDecisionAfter, managedDecision,
        };
        """,
        [origin, ordinary, managed],
    )
    require(isinstance(result, dict), f"unexpected credential state: {result!r}")
    return result


def start_browser(
    binary: Path, profile: Path, log_path: Path, *, headed: bool
) -> subprocess.Popen[str]:
    # A terminal started from a snap application can inherit that runtime's
    # private glibc library path. The unpacked Good Bear candidate is a host
    # binary, so it must not load snap's libpthread/libc pair.
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("SNAP")
        and name not in {"LD_LIBRARY_PATH", "LD_PRELOAD", "GTK_PATH"}
    } | {
        "LANG": "ru_RU.UTF-8",
        "LANGUAGE": "ru_RU:ru",
        "TMPDIR": str(ROOT / "artifacts/build-tmp"),
        "TMP": str(ROOT / "artifacts/build-tmp"),
        "TEMP": str(ROOT / "artifacts/build-tmp"),
    }
    if not headed:
        # This host has no usable SWGL framebuffer in headless mode.  Keep the
        # probe graphical-backend-independent; it validates browser state, not
        # compositor output.
        environment.update({"MOZ_HEADLESS": "1", "MOZ_WEBRENDER": "0"})
    return subprocess.Popen(
        [
            str(binary),
            *([] if headed else ["--headless"]),
            "--no-remote",
            "--marionette",
            "--remote-allow-system-access",
            "--profile",
            str(profile),
            "about:blank",
        ],
        stdout=log_path.open("a", encoding="utf-8"),
        stderr=subprocess.STDOUT,
        text=True,
        env=environment,
    )


def stop_browser(process: subprocess.Popen[str], client: Any | None) -> None:
    if client:
        try:
            client.delete_session()
        except Exception:
            pass
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def require_exact_state(state: dict[str, Any], token: str, *, controller: bool | None) -> None:
    for key in ("cookie", "localStorage", "indexedDB", "cache"):
        require(state.get(key) == token, f"{key} leaked or was unavailable: {state!r}")
    require(state.get("serviceWorker") is True, f"service worker registration missing: {state!r}")
    if controller is not None:
        require(state.get("controller") is controller, f"unexpected service-worker controller state: {state!r}")


def run(archive: Path, *, headed: bool) -> None:
    try:
        from marionette_driver.marionette import Marionette
    except ModuleNotFoundError as exc:
        raise ProbeError("run through the mach-Python wrapper") from exc
    try:
        verify_archive(archive)
    except ArchiveError as exc:
        raise ProbeError(f"archive precheck failed: {exc}") from exc

    server = ProbeServer()
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    proxy = ProbeProxy()
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    try:
        with temporary_directory(prefix="good-bear-m11-03-") as temporary:
            temporary = Path(temporary)
            binary = extract(archive, temporary / "archive")
            profile = temporary / "profile"
            profile.mkdir()
            (profile / "user.js").write_text(
                'user_pref("privacy.userContext.enabled", true);\n'
                'user_pref("extensions.formautofill.addresses.enabled", true);\n'
                'user_pref("extensions.formautofill.addresses.supported", "on");\n'
                'user_pref("dom.serviceWorkers.testing.enabled", true);\n',
                encoding="utf-8",
            )
            log_path = ROOT / "artifacts/logs/m11-03-storage-credentials-marionette.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            client: Any | None = None
            process = start_browser(binary, profile, log_path, headed=headed)
            try:
                print("[M11-03 live 1/7] Russian-only archive and fresh contextual-identity profile", flush=True)
                wait_for_marionette(process, profile, log_path)
                client = Marionette(host="127.0.0.1", port=2828, socket_timeout=60)
                client.start_session(timeout=60)
                require(not (profile / "cert_override.txt").exists(), "fresh profile has certificate overrides")
                managed = chrome_async(
                    client,
                    """
                    const container = ChromeUtils.importESModule(
                      "resource:///modules/GoodBearRussianPKIContainer.sys.mjs"
                    ).GoodBearRussianPKIContainer;
                    await container.initialize();
                    return container.dedicatedUserContextId;
                    """,
                )
                require(isinstance(managed, int) and managed > 0, f"invalid managed context: {managed!r}")

                ordinary_token, managed_token = "ordinary-m11-03", "managed-m11-03"
                print("[M11-03 live 2/7] Seeding ordinary and Russian-container web state", flush=True)
                ordinary_seed = open_state_tab(client, f"{server.origin}/state?mode=seed&token={ordinary_token}", 0)
                managed_seed = open_state_tab(client, f"{server.origin}/state?mode=seed&token={managed_token}", managed)
                require(ordinary_seed["userContextId"] == 0 and managed_seed["userContextId"] == managed, "tabs lost their container identities")
                require_exact_state(ordinary_seed, ordinary_token, controller=None)
                require_exact_state(managed_seed, managed_token, controller=None)

                print("[M11-03 live 3/7] Proving bidirectional web-store and service-worker separation", flush=True)
                ordinary_read = open_state_tab(client, f"{server.origin}/state?mode=read&token={ordinary_token}", 0)
                managed_read = open_state_tab(client, f"{server.origin}/state?mode=read&token={managed_token}", managed)
                require_exact_state(ordinary_read, ordinary_token, controller=True)
                require_exact_state(managed_read, managed_token, controller=True)

                print("[M11-03 live 4/7] Exercising login/autofill guards and client-auth OA keys", flush=True)
                credentials = credential_state(client, server.origin, 0, managed)
                require(credentials["ordinaryLogins"] > 0 and credentials["managedLogins"] == 0, f"saved-login boundary failed: {credentials!r}")
                # In the Russian locale, upstream FormAutofill can make its
                # ordinary actor unavailable by region before it reads a
                # profile record.  The seeded global count proves ordinary
                # profile data exists; our managed-context guard runs before
                # that availability gate and must never disclose it.
                require(credentials["beforeManagedWrite"] > 0 and credentials["managedRecords"] == 0, f"autofill read boundary failed: {credentials!r}")
                require(credentials["beforeManagedWrite"] == credentials["afterManagedWrite"], f"autofill write boundary failed: {credentials!r}")
                require(credentials["ordinaryDecision"] and not credentials["managedDecisionBefore"], f"client-auth ordinary-to-managed boundary failed: {credentials!r}")
                require(credentials["ordinaryDecisionAfter"] and credentials["managedDecision"], f"client-auth managed-to-ordinary boundary failed: {credentials!r}")

                print("[M11-03 live 5/7] Proving HTTP Basic cache isolation with native browser prompts", flush=True)
                run_auth_cache_direction(
                    client, server,
                    prefix="origin-ordinary-to-managed",
                    url_template=f"{server.origin}/basic?scope={{scope}}",
                    source_context=0, destination_context=managed,
                )
                run_auth_cache_direction(
                    client, server,
                    prefix="origin-managed-to-ordinary",
                    url_template=f"{server.origin}/basic?scope={{scope}}",
                    source_context=managed, destination_context=0,
                )

                print("[M11-03 live 6/7] Proving HTTP proxy-auth cache isolation with native browser prompts", flush=True)
                configure_loopback_proxy(client, proxy)
                try:
                    run_auth_cache_direction(
                        client, proxy,
                        prefix="proxy-ordinary-to-managed",
                        url_template="http://{scope}.m11-proxy.invalid/basic",
                        source_context=0, destination_context=managed,
                    )
                    run_auth_cache_direction(
                        client, proxy,
                        prefix="proxy-managed-to-ordinary",
                        url_template="http://{scope}.m11-proxy.invalid/basic",
                        source_context=managed, destination_context=0,
                    )
                finally:
                    clear_loopback_proxy(client)

            finally:
                stop_browser(process, client)

            print("[M11-03 live 7/7] Restarting the same profile and rechecking both directions", flush=True)
            client = None
            process = start_browser(binary, profile, log_path, headed=headed)
            try:
                wait_for_marionette(process, profile, log_path)
                client = Marionette(host="127.0.0.1", port=2828, socket_timeout=60)
                client.start_session(timeout=60)
                restarted_managed = chrome_async(client, """
                  const container = ChromeUtils.importESModule(
                    "resource:///modules/GoodBearRussianPKIContainer.sys.mjs"
                  ).GoodBearRussianPKIContainer;
                  await container.initialize(); return container.dedicatedUserContextId;
                """)
                require(restarted_managed == managed, "managed container identity did not persist across restart")
                require_exact_state(open_state_tab(client, f"{server.origin}/state?mode=read&token={ordinary_token}", 0), ordinary_token, controller=True)
                require_exact_state(open_state_tab(client, f"{server.origin}/state?mode=read&token={managed_token}", managed), managed_token, controller=True)
                require(not (profile / "cert_override.txt").exists(), "probe created a certificate exception")
            finally:
                stop_browser(process, client)
            success = f"PASS: M11-03 storage and credential isolation evidence; log: {log_path}"
            (ROOT / "artifacts/logs/m11-03-storage-credentials-result.log").write_text(
                success + "\n", encoding="utf-8"
            )
            print(success, flush=True)
    finally:
        server.shutdown()
        server.server_close()
        proxy.shutdown()
        proxy.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument(
        "--headed",
        action="store_true",
        help="use the local display if the host's headless SWGL compositor is unavailable",
    )
    parser.add_argument("--_inside-mach", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args._inside_mach:
        script = Path(__file__).resolve()
        child_args = [str(script), "--_inside-mach", "--archive", str(args.archive.resolve())]
        if args.headed:
            child_args.append("--headed")
        runner = (
            "import runpy, sys; "
            f"sys.path.insert(0, {str(ROOT / 'tools')!r}); "
            f"sys.argv = {child_args!r}; "
            f"runpy.run_path({str(script)!r}, run_name='__main__')"
        )
        return subprocess.call([str(SOURCE / "mach"), "python", "-c", runner], cwd=SOURCE)
    try:
        run(args.archive.resolve(), headed=args.headed)
    except Exception as exc:
        diagnostic_log = ROOT / "artifacts/logs/m11-03-storage-credentials-result.log"
        diagnostic_log.parent.mkdir(parents=True, exist_ok=True)
        diagnostic_log.write_text(f"ERROR: {exc}\n", encoding="utf-8")
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
