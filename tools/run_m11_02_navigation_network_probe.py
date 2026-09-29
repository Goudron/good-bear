#!/usr/bin/env python3
"""Exercise M11-02's assigned-origin isolation path through Marionette.

This is a focused host fallback for a browser-chrome harness failure.  It uses
a fresh Russian-only Good Bear profile and a public TLS origin, records Gecko's
HTTP observer notifications, rejects assigned-origin subresources in the
ordinary context, and never accepts a certificate exception.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time
from typing import Any

from project_temp import temporary_directory
from host_build_context import FIREFOX_WORKTREE_NAME, ROOT, SOURCE
from verify_russian_release_archive import ArchiveError, verify as verify_archive


FIREFOX_VERSION = FIREFOX_WORKTREE_NAME.removeprefix("firefox-")
DEFAULT_ARCHIVE = (
    ROOT
    / "artifacts/development/m15-02-ubuntu-obj/dist/"
    f"goodbear-1.0+firefox{FIREFOX_VERSION}.ru.linux-x86_64.tar.xz"
)
ORIGIN = "https://example.com"
PROBE_URL = f"{ORIGIN}/?goodbear-m11-02=network"
STICKY_URL = f"{ORIGIN}/?goodbear-m11-02=sticky"
COOKIE_NAME = "goodbear_m11_02"


class ProbeError(RuntimeError):
    pass


def extract(archive: Path, destination: Path) -> Path:
    try:
        with tarfile.open(archive, "r:xz") as bundle:
            bundle.extractall(destination, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise ProbeError(f"cannot extract archive: {exc}") from exc
    binary = destination / "goodbear" / "goodbear"
    if not binary.is_file():
        raise ProbeError(f"Good Bear executable is absent: {binary}")
    return binary


def chrome(client: Any, script: str, args: list[Any] | None = None) -> Any:
    client.set_context("chrome")
    return client.execute_script(script, script_args=args or [], sandbox=None)


def chrome_async(client: Any, script: str) -> Any:
    client.set_context("chrome")
    result = client.execute_async_script(
        f"""
        const done = arguments[arguments.length - 1];
        (async () => {{
          {script}
        }})().then(
          value => done({{ ok: true, value }}),
          error => done({{ ok: false, error: String(error), stack: error.stack }})
        );
        """,
        sandbox=None,
    )
    if not isinstance(result, dict) or not result.get("ok"):
        raise ProbeError(f"asynchronous chrome script failed: {result!r}")
    return result.get("value")


def content(client: Any, script: str, args: list[Any] | None = None) -> Any:
    client.set_context("content")
    return client.execute_script(script, script_args=args or [])


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


def state(client: Any) -> dict[str, Any]:
    result = chrome(
        client,
        """
        const w = Services.wm.getMostRecentWindow("navigator:browser");
        const container = ChromeUtils.importESModule(
          "resource:///modules/GoodBearRussianPKIContainer.sys.mjs"
        ).GoodBearRussianPKIContainer;
        return {
          dedicatedUserContextId: container.dedicatedUserContextId,
          tabs: [...w.gBrowser.tabs].map(tab => ({
            selected: tab === w.gBrowser.selectedTab,
            url: tab.linkedBrowser.currentURI.spec,
            userContextId: tab.linkedBrowser.browsingContext.originAttributes.userContextId,
            openerId: tab.linkedBrowser.browsingContext.opener?.id ?? null,
          })),
          events: w.__goodBearM1102NetworkEvents || [],
        };
        """,
    )
    if not isinstance(result, dict):
        raise ProbeError(f"unexpected browser state: {result!r}")
    return result


def wait_for_tab(client: Any, *, url: str, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        current = state(client)
        dedicated = current.get("dedicatedUserContextId")
        if isinstance(dedicated, int) and dedicated > 0 and any(
            tab.get("url") == url and tab.get("userContextId") == dedicated
            for tab in current.get("tabs", [])
            if isinstance(tab, dict)
        ):
            return current
        time.sleep(0.5)
    raise ProbeError(f"assigned navigation did not reach the dedicated tab: {state(client)!r}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeError(message)


def run(archive: Path, *, timeout_seconds: int) -> None:
    try:
        from marionette_driver.marionette import Marionette
    except ModuleNotFoundError as exc:
        raise ProbeError("run through the mach-Python wrapper") from exc
    try:
        verify_archive(archive)
    except ArchiveError as exc:
        raise ProbeError(f"archive precheck failed: {exc}") from exc

    with temporary_directory(prefix="good-bear-m11-02-network-") as temporary:
        temporary = Path(temporary)
        binary = extract(archive, temporary / "archive")
        profile = temporary / "profile"
        profile.mkdir()
        # A raw fresh profile does not enable native contextual identities by
        # default.  The shipped browser does; make the direct harness match
        # that condition before the first network context is created.
        (profile / "user.js").write_text(
            'user_pref("privacy.userContext.enabled", true);\n', encoding="utf-8"
        )
        log_path = ROOT / "artifacts/logs/m11-02-navigation-marionette.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        environment = os.environ | {
            "LANG": "ru_RU.UTF-8",
            "LANGUAGE": "ru_RU:ru",
            "TMPDIR": str(ROOT / "artifacts/build-tmp"),
            "TMP": str(ROOT / "artifacts/build-tmp"),
            "TEMP": str(ROOT / "artifacts/build-tmp"),
        }
        command = [
            str(binary),
            "--headless",
            "--no-remote",
            "--marionette",
            "--remote-allow-system-access",
            "--profile",
            str(profile),
            "about:blank",
        ]
        print("[M11-02 live 1/6] Russian-only archive verified", flush=True)
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, text=True, env=environment)
            client = Marionette(host="127.0.0.1", port=2828, socket_timeout=15)
            try:
                print("[M11-02 live 2/6] Starting a fresh-profile Marionette browser", flush=True)
                wait_for_marionette(process, profile, log_path)
                client.start_session(timeout=20)
                override = profile / "cert_override.txt"
                require(not override.exists(), "fresh profile unexpectedly has cert overrides")

                print("[M11-02 live 3/6] Seeding ordinary cookie and assigning TLS origin", flush=True)
                client.navigate(ORIGIN)
                cookie = content(
                    client,
                    "document.cookie = arguments[0]; return document.cookie;",
                    [f"{COOKIE_NAME}=ordinary; Secure; SameSite=None; Path=/"],
                )
                require(COOKIE_NAME in str(cookie), "ordinary source could not retain test cookie")
                chrome_async(
                    client,
                    """
                    const w = Services.wm.getMostRecentWindow("navigator:browser");
                    const container = ChromeUtils.importESModule(
                      "resource:///modules/GoodBearRussianPKIContainer.sys.mjs"
                    ).GoodBearRussianPKIContainer;
                    const policy = ChromeUtils.importESModule(
                      "resource:///modules/BrowserGlue.sys.mjs"
                    ).GoodBearRussianPKINavigationPolicy;
                    await container.initialize();
                    policy.start();
                    await container.assignmentStore.clear("https://example.com");
                    await container.assignmentStore.assign("https://example.com");
                    const events = [];
                    const observe = topic => subject => {
                      let channel;
                      try {
                        channel = subject.QueryInterface(Ci.nsIHttpChannel);
                      } catch {
                        return;
                      }
                      if (!channel.URI.spec.startsWith("https://example.com/")) {
                        return;
                      }
                      let cookie = "";
                      let referrer = "";
                      try { cookie = channel.getRequestHeader("Cookie"); } catch {}
                      try { referrer = channel.getRequestHeader("Referer"); } catch {}
                      events.push({
                        topic,
                        url: channel.URI.spec,
                        userContextId: channel.loadInfo?.originAttributes?.userContextId,
                        cookie,
                        referrer,
                      });
                    };
                    const before = observe("http-on-modify-request-before-cookies");
                    const sent = observe("http-on-modify-request");
                    const response = observe("http-on-examine-response");
                    Services.obs.addObserver(before, "http-on-modify-request-before-cookies");
                    Services.obs.addObserver(sent, "http-on-modify-request");
                    Services.obs.addObserver(response, "http-on-examine-response");
                    w.__goodBearM1102NetworkEvents = events;
                    w.__goodBearM1102NetworkObservers = { before, sent, response };
                    """,
                )

                subresource_rejections = chrome(
                    client,
                    """
                    const w = Services.wm.getMostRecentWindow("navigator:browser");
                    const policy = ChromeUtils.importESModule(
                      "resource:///modules/BrowserGlue.sys.mjs"
                    ).GoodBearRussianPKINavigationPolicy;
                    const loadInfo = {
                      originAttributes: { privateBrowsingId: 0, userContextId: 0 },
                      browsingContextID: w.gBrowser.selectedBrowser.browsingContext.id,
                    };
                    return [
                      Ci.nsIContentPolicy.TYPE_SCRIPT,
                      Ci.nsIContentPolicy.TYPE_IMAGE,
                      Ci.nsIContentPolicy.TYPE_SUBDOCUMENT,
                    ].map(type => policy.shouldLoad(
                      Services.io.newURI(arguments[0]),
                      { ...loadInfo, externalContentPolicyType: type }
                    ) === Ci.nsIContentPolicy.REJECT_POLICY);
                    """,
                    [ORIGIN],
                )
                require(
                    subresource_rejections == [True, True, True],
                    "assigned-origin script/image/subdocument escaped the ordinary-context barrier: "
                    f"{subresource_rejections!r}",
                )
                routing_classification = chrome(
                    client,
                    """
                    const { getRussianPKIRoutingCandidate } =
                      ChromeUtils.importESModule(
                        "resource:///actors/GoodBearRussianPKICertificateErrorChild.sys.mjs"
                      );
                    const candidateFor = securityInfo =>
                      getRussianPKIRoutingCandidate({
                        failedChannel: {
                          securityInfo,
                          QueryInterface() { return { requestMethod: "GET" }; },
                          URI: Services.io.newURI(arguments[0]),
                        },
                      });
                    return {
                      nativeFlagRoutes: candidateFor({
                        goodBearRussianPKIRequired: true,
                        errorCodeString: "SSL_ERROR_BAD_CERT_DOMAIN",
                      })?.url === Services.io.newURI(arguments[0]).spec,
                      stringOnlyRoutes: candidateFor({
                        errorCodeString: "SEC_ERROR_UNKNOWN_ISSUER",
                      }) !== null,
                    };
                    """,
                    [ORIGIN],
                )
                require(
                    routing_classification
                    == {"nativeFlagRoutes": True, "stringOnlyRoutes": False},
                    "error text spoofed or desynchronized native Russian-PKI routing: "
                    f"{routing_classification!r}",
                )
                body_replay_decision = chrome(
                    client,
                    """
                    const w = Services.wm.getMostRecentWindow("navigator:browser");
                    const policy = ChromeUtils.importESModule(
                      "resource:///modules/BrowserGlue.sys.mjs"
                    ).GoodBearRussianPKINavigationPolicy;
                    const uri = Services.io.newURI(arguments[0]);
                    const originAttributes = { privateBrowsingId: 0, userContextId: 0 };
                    const originalSchedule = policy._scheduleAddressOnlyOpen;
                    let scheduled = null;
                    let cancelReason = null;
                    policy._scheduleAddressOnlyOpen = (...args) => {
                      scheduled = args[3];
                    };
                    try {
                      policy._cancelIfOrdinaryAssignedRequest(
                        {
                          URI: uri,
                          requestMethod: "POST",
                          loadInfo: {
                            originAttributes,
                            browsingContextID:
                              w.gBrowser.selectedBrowser.browsingContext.id,
                            externalContentPolicyType:
                              Ci.nsIContentPolicy.TYPE_DOCUMENT,
                          },
                          cancel(reason) { cancelReason = reason; },
                        },
                        uri,
                        originAttributes
                      );
                    } finally {
                      policy._scheduleAddressOnlyOpen = originalSchedule;
                    }
                    return {
                      cancelled: cancelReason === Cr.NS_ERROR_BLOCKED_BY_POLICY,
                      scheduled: scheduled !== null,
                      autoOpen: scheduled?.autoOpen ?? null,
                      hasRequestBody: scheduled?.hasRequestBody ?? null,
                    };
                    """,
                    [ORIGIN],
                )
                require(
                    body_replay_decision
                    == {
                        "cancelled": True,
                        "scheduled": True,
                        "autoOpen": False,
                        "hasRequestBody": True,
                    },
                    "ordinary POST was replayable across the container boundary: "
                    f"{body_replay_decision!r}",
                )

                print("[M11-02 live 4/6] Opening the known origin from ordinary state", flush=True)
                content(client, "window.open(arguments[0], '_blank');", [PROBE_URL])
                current = wait_for_tab(client, url=PROBE_URL, timeout_seconds=timeout_seconds)
                dedicated = current["dedicatedUserContextId"]
                managed_tab = next(
                    tab for tab in current["tabs"]
                    if tab.get("url") == PROBE_URL and tab.get("userContextId") == dedicated
                )
                require(
                    managed_tab.get("openerId") is None,
                    f"managed tab retained an ordinary opener: {managed_tab!r}",
                )
                events = current["events"]
                normal_responses = [
                    event for event in events
                    if event["topic"] == "http-on-examine-response" and event["url"] == PROBE_URL
                    and event["userContextId"] == 0
                ]
                managed_sent = [
                    event for event in events
                    if event["topic"] == "http-on-modify-request" and event["url"] == PROBE_URL
                    and event["userContextId"] == dedicated
                ]
                managed_responses = [
                    event for event in events
                    if event["topic"] == "http-on-examine-response" and event["url"] == PROBE_URL
                    and event["userContextId"] == dedicated
                ]
                require(
                    not normal_responses,
                    f"ordinary request reached a response boundary: {normal_responses!r}",
                )
                require(managed_sent, "managed request was not observed at network boundary")
                require(managed_responses, "managed request did not receive a response")
                require(all(COOKIE_NAME not in event["cookie"] for event in managed_sent), "ordinary cookie reached managed network request")
                require(all(not event["referrer"] for event in managed_sent), "ordinary referrer reached managed network request")

                print("[M11-02 live 5/6] Checking sticky navigation and assignment reset", flush=True)
                chrome(
                    client,
                    """
                    const w = Services.wm.getMostRecentWindow("navigator:browser");
                    const tab = [...w.gBrowser.tabs].find(tab =>
                      tab.linkedBrowser.currentURI.spec === arguments[0] &&
                      tab.linkedBrowser.browsingContext.originAttributes.userContextId === arguments[1]
                    );
                    w.gBrowser.selectedTab = tab;
                    tab.linkedBrowser.loadURI(Services.io.newURI(arguments[2]), {
                      triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
                    });
                    """,
                    [PROBE_URL, dedicated, STICKY_URL],
                )
                sticky = wait_for_tab(client, url=STICKY_URL, timeout_seconds=timeout_seconds)
                require(any(
                    tab.get("url") == STICKY_URL and tab.get("userContextId") == dedicated
                    for tab in sticky["tabs"] if isinstance(tab, dict)
                ), "sticky navigation left the dedicated tab")
                ordinary_after_reset = chrome_async(
                    client,
                    """
                    const container = ChromeUtils.importESModule(
                      "resource:///modules/GoodBearRussianPKIContainer.sys.mjs"
                    ).GoodBearRussianPKIContainer;
                    await container.assignmentStore.clear("https://example.com");
                    return container.getLoadDecision("https://example.com", 0).type;
                    """,
                )
                require(ordinary_after_reset == "ordinary", "reset did not restore ordinary classification")
                require(not override.exists(), "probe created a certificate exception")
                print(
                    "[M11-02 live 6/6] PASS: native routing, body, network state, and subresources stayed isolated",
                    flush=True,
                )
            finally:
                try:
                    chrome(
                        client,
                        """
                        const w = Services.wm.getMostRecentWindow("navigator:browser");
                        const observers = w?.__goodBearM1102NetworkObservers;
                        if (observers) {
                          Services.obs.removeObserver(observers.before, "http-on-modify-request-before-cookies");
                          Services.obs.removeObserver(observers.sent, "http-on-modify-request");
                          Services.obs.removeObserver(observers.response, "http-on-examine-response");
                        }
                        """,
                    )
                except Exception:
                    pass
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
        print(f"Marionette log: {log_path}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--_inside-mach", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.timeout_seconds < 10:
        parser.error("--timeout-seconds must be at least 10")
    if not args._inside_mach:
        script = Path(__file__).resolve()
        child_args = [
            str(script), "--_inside-mach", "--archive", str(args.archive.resolve()),
            "--timeout-seconds", str(args.timeout_seconds),
        ]
        runner = (
            "import runpy, sys; "
            f"sys.path.insert(0, {str(ROOT / 'tools')!r}); "
            f"sys.argv = {child_args!r}; "
            f"runpy.run_path({str(script)!r}, run_name='__main__')"
        )
        return subprocess.call([str(SOURCE / "mach"), "python", "-c", runner], cwd=SOURCE)
    try:
        run(args.archive.resolve(), timeout_seconds=args.timeout_seconds)
    except ProbeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
