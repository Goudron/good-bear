#!/usr/bin/env python3
"""Run fresh-profile GB100-M11-04 Russian UI, private, and 0-RTT checks.

This is runtime evidence complementary to browser-chrome/xpcshell owners. It
does not accept certificate overrides, uses a Russian-only archive, and keeps
all temporary extraction/profile data on the project filesystem. The 0-RTT
packet/server assertion itself remains in the named xpcshell test because the
browser automation API cannot observe TLS bytes before certificate validation.
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
    ROOT / "artifacts/development/m15-02-ubuntu-obj/dist/"
    f"goodbear-1.0+firefox{FIREFOX_VERSION}.ru.linux-x86_64.tar.xz"
)
FSTEC_URL = "https://fstec.ru/"


class ProbeError(RuntimeError):
    pass


def extract_archive(archive: Path, destination: Path) -> Path:
    try:
        with tarfile.open(archive, "r:xz") as bundle:
            bundle.extractall(destination, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise ProbeError(f"cannot extract archive: {exc}") from exc
    binary = destination / "goodbear" / "goodbear"
    if not binary.is_file():
        raise ProbeError(f"Good Bear executable is missing: {binary}")
    return binary


def wait_for_marionette(process: subprocess.Popen[str], profile: Path, log: Path) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        active = profile / "MarionetteActivePort"
        if active.is_file() and active.read_text(encoding="ascii").strip() == "2828":
            return
        if process.poll() is not None:
            raise ProbeError(f"Good Bear exited before Marionette was ready; see {log}")
        time.sleep(0.2)
    raise ProbeError("Good Bear did not expose Marionette on port 2828")


def eventually(client: Any, script: str, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        value = client.execute_script(script, sandbox=None)
        if isinstance(value, dict):
            last = value
            if value.get("ready"):
                return value
        time.sleep(1)
    raise ProbeError(f"Russian PKI runtime state was not ready: {last!r}")


def run(archive: Path, *, timeout_seconds: int, headless: bool) -> None:
    try:
        from marionette_driver.marionette import Marionette
    except ModuleNotFoundError as exc:
        raise ProbeError("Marionette dependencies are unavailable") from exc
    try:
        verify_archive(archive)
    except ArchiveError as exc:
        raise ProbeError(f"Russian-only archive precheck failed: {exc}") from exc

    with temporary_directory(prefix="good-bear-m11-04-") as temporary:
        work = Path(temporary)
        binary = extract_archive(archive, work / "archive")
        profile = work / "profile"
        profile.mkdir()
        log_path = ROOT / "artifacts/logs/m11-04-ui-private-marionette.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        command = [
            str(binary),
            *([] if not headless else ["--headless"]),
            "--no-remote",
            "--marionette",
            "--remote-allow-system-access",
            "--profile",
            str(profile),
            "about:blank",
        ]
        environment = os.environ | {
            "LANG": "ru_RU.UTF-8",
            "LANGUAGE": "ru_RU:ru",
            "TMPDIR": str(ROOT / "artifacts/build-tmp"),
            "TMP": str(ROOT / "artifacts/build-tmp"),
            "TEMP": str(ROOT / "artifacts/build-tmp"),
        }
        print("[M11-04 1/5] Russian-only archive verified; launching fresh profile", flush=True)
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, text=True, env=environment)
            client = Marionette(host="127.0.0.1", port=2828, socket_timeout=15)
            try:
                wait_for_marionette(process, profile, log_path)
                client.start_session(timeout=20)
                client.set_context("chrome")
                client.execute_script(
                    'Services.prefs.setBoolPref("privacy.userContext.enabled", true);', sandbox=None
                )
                override = profile / "cert_override.txt"
                if override.exists():
                    raise ProbeError("fresh profile unexpectedly contains certificate overrides")

                print("[M11-04 2/5] Checking Russian locale and localized Good Bear UI strings", flush=True)
                locale = client.execute_script(
                    """
                    const w = Services.wm.getMostRecentWindow("navigator:browser");
                    const ids = [
                      "identity-goodbear-russian-pki-label",
                      "identity-goodbear-russian-pki-description",
                    ];
                    return Promise.all(ids.map(id => w.document.l10n.formatValue(id))).then(values => ({
                      locale: Services.locale.appLocaleAsBCP47,
                      values,
                    }));
                    """,
                    sandbox=None,
                )
                if (
                    not isinstance(locale, dict)
                    or locale.get("locale") != "ru"
                    or locale.get("values") != [
                        "RU",
                        "Good Bear распознал в качестве издателя сертификата этого веб-сайта Минцифры РФ. Он был открыт в специальном защищённом контейнере отдельно от других веб-сайтов.",
                    ]
                ):
                    raise ProbeError(f"Russian locale/UI resolution failed: {locale!r}")

                print("[M11-04 3/5] Opening FSTEC and checking native badge/popup state", flush=True)
                client.execute_script(
                    f"""
                    const w = Services.wm.getMostRecentWindow("navigator:browser");
                    w.gBrowser.selectedBrowser.loadURI(Services.io.newURI({FSTEC_URL!r}), {{
                      triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
                    }});
                    """,
                    sandbox=None,
                )
                state = eventually(
                    client,
                    """
                    const w = Services.wm.getMostRecentWindow("navigator:browser");
                    const tab = [...w.gBrowser.tabs].find(t =>
                      t.linkedBrowser.currentURI.spec === "https://fstec.ru/" &&
                      t.linkedBrowser.securityUI?.secInfo?.goodBearTrustDomain === 2
                    );
                    if (!tab) return {ready: false};
                    w.gBrowser.selectedTab = tab;
                    // The identity panel is lazily stamped from its template.
                    // Instantiate it before inspecting popup/subview attributes.
                    w.gIdentityHandler._initializePopup();
                    w.gIdentityHandler.refreshIdentityBlock();
                    w.gIdentityHandler.refreshIdentityPopup();
                    const label = w.document.getElementById("trust-goodbear-russian-pki-label");
                    const popup = w.document.getElementById("identity-popup");
                    const extended = w.document.getElementById("identity-popup-securityView-extended-info");
                    return {
                      ready: true,
                      contextId: tab.linkedBrowser.browsingContext.originAttributes.userContextId,
                      trustDomain: tab.linkedBrowser.securityUI.secInfo.goodBearTrustDomain,
                      badge: label.getAttribute("value") || label.value || label.textContent,
                      badgeHidden: label.hidden || label.collapsed,
                      badgeL10n: label.getAttribute("data-l10n-id"),
                      popupDomain: popup.getAttribute("goodbear-trust-domain"),
                      extendedDomain: extended.getAttribute("goodbear-trust-domain"),
                      russianNative: w.gIdentityHandler._usesGoodBearRussianPKI,
                    };
                    """,
                    timeout_seconds,
                )
                if (
                    state.get("trustDomain") != 2
                    or state.get("contextId", 0) <= 0
                    or state.get("badge") != "RU"
                    or state.get("badgeHidden")
                    or state.get("badgeL10n") != "identity-goodbear-russian-pki-label"
                    or state.get("popupDomain") != "russian-pki"
                    or state.get("extendedDomain") != "russian-pki"
                    or not state.get("russianNative")
                ):
                    raise ProbeError(f"native Russian PKI UI state is incomplete: {state!r}")

                print("[M11-04 4/5] Proving Private Browsing cannot receive alternate trust", flush=True)
                private_state = client.execute_script(
                    """
                    const normal = Services.wm.getMostRecentWindow("navigator:browser");
                    const container = ChromeUtils.importESModule(
                      "resource:///modules/GoodBearRussianPKIContainer.sys.mjs"
                    ).GoodBearRussianPKIContainer;
                    const id = container.dedicatedUserContextId;
                    const authority = Cc["@mozilla.org/psm;1"].getService(Ci.nsINSSComponent);
                    const privateWindow = OpenBrowserWindow({private: true});
                    return new Promise(resolve => privateWindow.addEventListener("load", () => {
                      resolve({
                        contextId: id,
                        privateBrowsingId: privateWindow.gBrowser.selectedBrowser.browsingContext.originAttributes.privateBrowsingId,
                        allowed: authority.isGoodBearRussianPKIContainer(id, true),
                      });
                      privateWindow.close();
                    }, {once: true}));
                    """,
                    sandbox=None,
                )
                if (
                    not isinstance(private_state, dict)
                    or private_state.get("contextId", 0) <= 0
                    or private_state.get("privateBrowsingId") != 1
                    or private_state.get("allowed") is not False
                ):
                    raise ProbeError(f"Private Browsing did not fail closed: {private_state!r}")

                print("[M11-04 5/5] PASS: runtime UI/PB gates passed; run xpcshell T25 separately", flush=True)
                if override.exists():
                    raise ProbeError("probe created certificate overrides; evidence is invalid")
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
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--_inside-mach", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.timeout_seconds < 10:
        parser.error("--timeout-seconds must be at least 10")
    if not args._inside_mach:
        script = Path(__file__).resolve()
        child_args = [str(script), "--_inside-mach", "--archive", str(args.archive.resolve()), "--timeout-seconds", str(args.timeout_seconds)]
        if args.headed:
            child_args.append("--headed")
        runner = "import runpy, sys; " + f"sys.path.insert(0, {str(ROOT / 'tools')!r}); sys.argv = {child_args!r}; " + f"runpy.run_path({str(script)!r}, run_name='__main__')"
        return subprocess.call([str(SOURCE / "mach"), "python", "-c", runner], cwd=SOURCE)
    try:
        run(args.archive.resolve(), timeout_seconds=args.timeout_seconds, headless=not args.headed)
    except ProbeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
