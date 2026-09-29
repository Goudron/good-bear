#!/usr/bin/env python3
"""Run the opt-in live FSTEC Russian-PKI integration check.

This is deliberately not part of the offline build gate: it contacts the
public ``https://fstec.ru/`` endpoint.  It starts the supplied Russian-only
Good Bear archive through direct Marionette with a newly-created profile and proves
the user-visible first-visit path end to end.  A certificate exception in a
developer profile is never accepted as evidence.
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
FSTEC_URL = "https://fstec.ru/"
RUSSIAN_PKI_TRUST_DOMAIN = 2
RUSSIAN_PKI_LABEL = "RU"


class LiveCheckError(RuntimeError):
    pass


def browser_binary(extracted: Path) -> Path:
    binary = extracted / "goodbear" / "goodbear"
    if not binary.is_file():
        raise LiveCheckError(f"Good Bear executable is missing from archive: {binary}")
    return binary


def extract_archive(archive: Path, destination: Path) -> Path:
    try:
        with tarfile.open(archive, "r:xz") as bundle:
            bundle.extractall(destination, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise LiveCheckError(f"cannot extract {archive}: {exc}") from exc
    return destination


def successful_fstec_tab(state: dict[str, Any]) -> dict[str, Any] | None:
    dedicated = state.get("dedicatedUserContextId")
    if not isinstance(dedicated, int) or dedicated <= 0:
        return None
    for tab in state.get("tabs", []):
        if (
            isinstance(tab, dict)
            and tab.get("url") == FSTEC_URL
            and tab.get("userContextId") == dedicated
            and tab.get("trustDomain") == RUSSIAN_PKI_TRUST_DOMAIN
        ):
            return tab
    return None


def successful_fstec_tabs(state: dict[str, Any]) -> list[dict[str, Any]]:
    dedicated = state.get("dedicatedUserContextId")
    if not isinstance(dedicated, int) or dedicated <= 0:
        return []
    return [
        tab
        for tab in state.get("tabs", [])
        if (
            isinstance(tab, dict)
            and tab.get("url") == FSTEC_URL
            and tab.get("userContextId") == dedicated
            and tab.get("trustDomain") == RUSSIAN_PKI_TRUST_DOMAIN
        )
    ]


def marionette_state(client: Any) -> dict[str, Any]:
    state = client.execute_script(
        """
        const w = Services.wm.getMostRecentWindow("navigator:browser");
        const container = ChromeUtils.importESModule(
          "resource:///modules/GoodBearRussianPKIContainer.sys.mjs"
        ).GoodBearRussianPKIContainer;
        return {
          dedicatedUserContextId: container.dedicatedUserContextId,
          tabs: [...w.gBrowser.tabs].map(tab => {
            const browser = tab.linkedBrowser;
            return {
              url: browser.currentURI.spec,
              selected: tab === w.gBrowser.selectedTab,
              userContextId: browser.browsingContext.originAttributes.userContextId,
              trustDomain: browser.securityUI?.secInfo?.goodBearTrustDomain ?? null,
            };
          }),
        };
        """,
        sandbox=None,
    )
    if not isinstance(state, dict):
        raise LiveCheckError(f"unexpected browser state: {state!r}")
    return state


def marionette_visible_indicator(client: Any) -> dict[str, Any]:
    indicator = client.execute_script(
        """
        const w = Services.wm.getMostRecentWindow("navigator:browser");
        const target = [...w.gBrowser.tabs].find(tab => {
          const browser = tab.linkedBrowser;
          return browser.currentURI.spec === "https://fstec.ru/" &&
            browser.securityUI?.secInfo?.goodBearTrustDomain === 2;
        });
        if (!target) {
          return null;
        }
        w.gBrowser.selectedTab = target;
        const label = w.document.getElementById(
          "trust-goodbear-russian-pki-label"
        );
        return {
          usesRussianPKI: w.gIdentityHandler._usesGoodBearRussianPKI,
          collapsed: label.collapsed,
          hidden: label.hidden,
          l10nId: label.getAttribute("data-l10n-id"),
          value: label.getAttribute("value") || label.value || label.textContent,
        };
        """,
        sandbox=None,
    )
    if not isinstance(indicator, dict):
        raise LiveCheckError("the successful FSTEC tab has no identity indicator")
    return indicator


def marionette_persisted_fstec_assignment(client: Any) -> bool:
    """Return whether the first native result has committed its exact origin.

    A successful TLS result is delivered before the response observer's
    deliberately asynchronous profile transaction finishes.  A second normal
    navigation must therefore wait for the assignment to be persisted and
    published to the native HTTP guard; otherwise this integration check races
    the very fail-closed route it is intended to verify.
    """
    assigned = client.execute_script(
        """
        const container = ChromeUtils.importESModule(
          "resource:///modules/GoodBearRussianPKIContainer.sys.mjs"
        ).GoodBearRussianPKIContainer;
        return container.assignmentStore.isAssigned(
          Services.io.newURI("https://fstec.ru/")
        );
        """,
        sandbox=None,
    )
    return assigned is True


def run(archive: Path, *, timeout_seconds: int, headless: bool) -> None:
    try:
        from marionette_driver.marionette import Marionette
    except ModuleNotFoundError as exc:
        raise LiveCheckError(
            "Marionette dependencies are unavailable; invoke this tool through its normal wrapper"
        ) from exc
    archive = archive.resolve()
    try:
        verify_archive(archive)
    except ArchiveError as exc:
        raise LiveCheckError(f"Russian-only archive precheck failed: {exc}") from exc

    with temporary_directory(prefix="good-bear-fstec-live-") as temporary:
        work = Path(temporary)
        extracted = extract_archive(archive, work / "archive")
        binary = browser_binary(extracted)
        profile = work / "profile"
        profile.mkdir()
        log_path = ROOT / "artifacts/logs/fstec-live-marionette.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        command = [
            str(binary),
            *( [] if not headless else ["--headless"] ),
            "--no-remote",
            "--marionette",
            "--remote-allow-system-access",
            "--profile",
            str(profile),
            "about:blank",
        ]
        print("[FSTEC live 1/7] Russian-only archive verified", flush=True)
        print("[FSTEC live 2/7] Starting Good Bear with a fresh profile", flush=True)
        environment = os.environ | {
            "LANG": "ru_RU.UTF-8",
            "LANGUAGE": "ru_RU:ru",
            "TMPDIR": str(ROOT / "artifacts/build-tmp"),
            "TMP": str(ROOT / "artifacts/build-tmp"),
            "TEMP": str(ROOT / "artifacts/build-tmp"),
        }
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                command, stdout=log, stderr=subprocess.STDOUT, text=True, env=environment
            )
            client = Marionette(host="127.0.0.1", port=2828, socket_timeout=15)
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    log.flush()
                    active_port = profile / "MarionetteActivePort"
                    if (
                        active_port.is_file()
                        and active_port.read_text(encoding="ascii").strip() == "2828"
                        and "Listening on port 2828" in log_path.read_text(
                        encoding="utf-8", errors="replace"
                        )
                    ):
                        break
                    if process.poll() is not None:
                        raise LiveCheckError(
                            f"Good Bear exited before Marionette was ready; see {log_path}"
                        )
                    time.sleep(0.2)
                else:
                    raise LiveCheckError("Good Bear did not expose Marionette on 127.0.0.1:2828")
                client.start_session(timeout=20)
                client.set_context("chrome")
                override = profile / "cert_override.txt"
                if override.exists():
                    raise LiveCheckError("fresh live-test profile unexpectedly contains cert_override.txt")

                print("[FSTEC live 3/7] Opening FSTEC in an ordinary first-visit tab", flush=True)
                client.execute_script(
                    """
                    const w = Services.wm.getMostRecentWindow("navigator:browser");
                    w.gBrowser.selectedBrowser.loadURI(
                      Services.io.newURI("https://fstec.ru/"),
                      {
                        triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
                      }
                    );
                    """,
                    sandbox=None,
                )
                deadline = time.monotonic() + timeout_seconds
                state: dict[str, Any] | None = None
                while time.monotonic() < deadline:
                    state = marionette_state(client)
                    if successful_fstec_tab(state):
                        break
                    time.sleep(1)
                if not state or not successful_fstec_tab(state):
                    raise LiveCheckError(
                        "FSTEC was not automatically reopened in the dedicated Russian PKI "
                        f"container before timeout; last state: {state!r}"
                    )
                if override.exists():
                    raise LiveCheckError("the live test created a certificate override; result is invalid")

                print("[FSTEC live 4/7] Confirming native RussianPKI result and UI marker", flush=True)
                indicator = marionette_visible_indicator(client)
                if (
                    indicator.get("collapsed")
                    or indicator.get("hidden")
                    or indicator.get("l10nId") != "identity-goodbear-russian-pki-label"
                    or indicator.get("value") != RUSSIAN_PKI_LABEL
                    or not indicator.get("usesRussianPKI")
                ):
                    raise LiveCheckError(f"Russian PKI indicator is not the visible compact RU marker: {indicator!r}")
                print("[FSTEC live 5/7] Waiting for the exact FSTEC assignment", flush=True)
                deadline = time.monotonic() + timeout_seconds
                while time.monotonic() < deadline:
                    if marionette_persisted_fstec_assignment(client):
                        break
                    time.sleep(1)
                else:
                    raise LiveCheckError(
                        "the successful first FSTEC visit did not persist its exact "
                        "Russian PKI assignment before timeout"
                    )

                print("[FSTEC live 6/7] Reopening FSTEC from a second ordinary tab", flush=True)
                client.execute_script(
                    """
                    const w = Services.wm.getMostRecentWindow("navigator:browser");
                    const tab = w.gBrowser.addTab("about:blank", {
                      userContextId: 0,
                      triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
                    });
                    w.gBrowser.selectedTab = tab;
                    tab.linkedBrowser.loadURI(Services.io.newURI("https://fstec.ru/"), {
                      triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
                    });
                    """,
                    sandbox=None,
                )
                deadline = time.monotonic() + timeout_seconds
                while time.monotonic() < deadline:
                    state = marionette_state(client)
                    if len(successful_fstec_tabs(state)) >= 2:
                        break
                    time.sleep(1)
                if not state or len(successful_fstec_tabs(state)) < 2:
                    raise LiveCheckError(
                        "a second ordinary FSTEC tab did not reopen in the dedicated "
                        f"Russian PKI container; last state: {state!r}"
                    )
                print("[FSTEC live 7/7] PASS: repeated ordinary navigation is isolated too", flush=True)
            finally:
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
    parser.add_argument("--timeout-seconds", type=int, default=45)
    parser.add_argument("--headed", action="store_true", help="show the test browser window")
    parser.add_argument("--_inside-mach", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.timeout_seconds < 10:
        parser.error("--timeout-seconds must be at least 10")
    archive = args.archive.resolve()
    if not args._inside_mach:
        script = Path(__file__).resolve()
        child_args = [
            str(script),
            "--_inside-mach",
            "--archive",
            str(archive),
            "--timeout-seconds",
            str(args.timeout_seconds),
        ]
        if args.headed:
            child_args.append("--headed")
        runner = (
            "import runpy, sys; "
            f"sys.path.insert(0, {str(ROOT / 'tools')!r}); "
            f"sys.argv = {child_args!r}; "
            f"runpy.run_path({str(script)!r}, run_name='__main__')"
        )
        command = [str(SOURCE / "mach"), "python", "-c", runner]
        return subprocess.call(command, cwd=SOURCE)
    try:
        run(archive, timeout_seconds=args.timeout_seconds, headless=not args.headed)
    except LiveCheckError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
