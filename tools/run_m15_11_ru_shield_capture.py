#!/usr/bin/env python3
"""Capture actual Russian RU/shield UI; never approve a visual baseline.

This bounded runner covers the native Russian-PKI shield, hover, keyboard
focus, and its popup in light/dark at 1/1.25 scale. The remaining M15-11
surfaces, OS matrix and manual comparison remain separate acceptance work.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

from host_build_context import ROOT, SOURCE
from project_temp import temporary_directory
from run_m11_04_ui_private_early_probe import (
    DEFAULT_ARCHIVE, FSTEC_URL, ProbeError, eventually, extract_archive,
    wait_for_marionette,
)
from verify_russian_release_archive import verify as verify_archive


BASELINE = ROOT / "config/firefox-baseline.json"
WINDOW = 'const w = Services.wm.getMostRecentWindow("navigator:browser");'
THEMES = {
    "light": "firefox-compact-light@mozilla.org",
    "dark": "firefox-compact-dark@mozilla.org",
}


def prerequisites(archive: Path) -> dict:
    baseline = json.loads(BASELINE.read_text())
    reasons = []
    if not archive.is_file():
        reasons.append(f"Pinned {baseline['version']} Russian archive is unavailable: {archive}")
    driver = importlib.util.find_spec("marionette_driver") is not None
    return {
        "status": "blocked" if reasons else "archive_available_runtime_unverified",
        "reasons": reasons,
        "archive": str(archive),
        "firefox_version": baseline["version"],
        "upstream_revision": baseline["vcs"]["revision"],
        "marionette_driver_available": driver,
        "mach_bootstrap_available": (SOURCE / "mach").is_file(),
        "runtime_verified": False,
        "visual_parity_proven": False,
        "promotion_allowed": False,
    }


def validate_identity(identity: dict, version: str) -> None:
    if identity.get("locale") != "ru" or identity.get("platform_version") != version:
        raise ProbeError("Runtime is not the pinned Firefox platform with Russian startup locale")


def validate_ru_state(state: dict, *, scale: float | None = None) -> None:
    if (
        state.get("trust_domain") != 2
        or state.get("context_id", 0) <= 0
        or state.get("private_id") != 0
        or state.get("badge") != "RU"
        or state.get("badge_visible") is not True
        or state.get("describedby") != "trust-goodbear-russian-pki-description"
    ):
        raise ProbeError("Capture requires real native Russian-PKI trust and its scoped, visible RU badge")
    if scale is not None and (
        state.get("viewport") != [1920, 1080]
        or abs(state.get("device_pixel_ratio", 0) - scale) > 0.01
    ):
        raise ProbeError("Actual viewport or device scale does not match the requested capture")


STATE = WINDOW + r"""
const browser = w.gBrowser.selectedBrowser;
const badge = w.document.getElementById("trust-goodbear-russian-pki-label");
const shield = w.document.getElementById("trust-icon-container");
const icon = w.document.getElementById("trust-icon");
const rect = node => {
  const r = node.getBoundingClientRect();
  return {x:r.x, y:r.y, width:r.width, height:r.height};
};
const oa = browser.browsingContext.originAttributes;
const state = {
  trust_domain: browser.securityUI?.secInfo?.goodBearTrustDomain,
  context_id: oa.userContextId, private_id: oa.privateBrowsingId,
  badge: badge?.getAttribute("value") || badge?.textContent,
  badge_visible: !!badge?.checkVisibility(),
  describedby: shield?.getAttribute("aria-describedby"),
  shield_label: shield?.getAttribute("aria-label"),
  shield_class: shield?.className?.baseVal ?? shield?.getAttribute("class"),
  shield_state: shield?.getAttribute("state"),
  viewport: [w.innerWidth, w.innerHeight], device_pixel_ratio: w.devicePixelRatio,
  forced_colors: w.matchMedia("(forced-colors: active)").matches,
  keyboard_focus: shield?.matches(":focus-visible"),
  hover: shield?.matches(":hover"),
  badge_rect: badge && rect(badge), shield_rect: shield && rect(shield),
  icon_image: icon && w.getComputedStyle(icon).listStyleImage,
};
state.ready = state.trust_domain === 2 && state.badge_visible;
return state;
"""


def resize_viewport(client, scale: float) -> None:
    client.execute_script(
        'Services.prefs.setCharPref("layout.css.devPixelsPerPx", arguments[0]);',
        script_args=[str(scale)], sandbox=None,
    )
    for _ in range(3):
        dimensions = client.execute_script(
            WINDOW + "return [w.innerWidth,w.innerHeight,w.outerWidth,w.outerHeight];",
            sandbox=None,
        )
        client.set_window_rect(
            width=dimensions[2] + 1920 - dimensions[0],
            height=dimensions[3] + 1080 - dimensions[1],
        )
    client.execute_async_script(
        WINDOW + "const done=arguments[arguments.length-1]; w.requestAnimationFrame(() => w.requestAnimationFrame(done));",
        sandbox=None,
    )


def capture(client, output: Path, report: dict, theme: str, scale: float, state_name: str) -> None:
    state = client.execute_script(STATE, sandbox=None)
    validate_ru_state(state, scale=scale)
    if state_name == "hover" and not state["hover"]:
        raise ProbeError("The real pointer did not enter the native shield")
    if state_name == "keyboard_focus" and not state["keyboard_focus"]:
        raise ProbeError("The native shield did not receive visible keyboard focus")
    raw = client.screenshot(format="binary", full=False)
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ProbeError("Marionette did not return a PNG screenshot")
    filename = f"{theme}-{scale:g}-{state_name}.png"
    (output / filename).write_bytes(raw)
    report["captures"].append({
        "file": filename, "sha256": hashlib.sha256(raw).hexdigest(),
        "theme": theme, "scale": scale, "state": state_name,
        "observed": state,
    })
    (output / "capture.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(f"[M15-11] captured {filename}", flush=True)


def run(archive: Path, output: Path, *, headed: bool) -> None:
    from marionette_driver.marionette import Marionette
    from marionette_driver.keys import Keys
    from marionette_driver.by import By

    preflight = prerequisites(archive)
    if preflight["reasons"]:
        raise ProbeError("; ".join(preflight["reasons"]))
    verify_archive(archive)
    output.mkdir(parents=True, exist_ok=False)
    with archive.open("rb") as stream:
        archive_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    report = preflight | {
        "status": "capture_in_progress", "archive_sha256": archive_hash,
        "source_provenance_verified": False,
        "host": platform.platform(), "headless": not headed, "captures": [],
        "capture_scope": ["russian_pki_trust_indicator", "security_popup"],
        "manual_promotion": None,
        "remaining_acceptance": [
            "Full M15-11 surface/state/OS matrix and high-contrast review",
            "Native standard/invalid certificate and tracker-count transitions",
            "155-to-156 visual comparison and named manual promotion",
        ],
    }
    with temporary_directory(prefix="good-bear-m15-11-") as temporary:
        work = Path(temporary)
        binary = extract_archive(archive, work / "archive")
        profile = work / "profile"
        profile.mkdir()
        log_path = output / "browser.log"
        environment = os.environ | {
            "LANG": "ru_RU.UTF-8", "LANGUAGE": "ru_RU:ru",
            "TMPDIR": str(work), "TMP": str(work), "TEMP": str(work),
            "MOZ_HEADLESS_WIDTH": "2560", "MOZ_HEADLESS_HEIGHT": "1600",
        }
        command = [str(binary), *([] if headed else ["--headless"]),
                   "--no-remote", "--marionette", "--remote-allow-system-access",
                   "--profile", str(profile), "about:blank"]
        print("[M15-11] Launching verified Russian archive with fresh profile", flush=True)
        with log_path.open("w") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       text=True, env=environment)
            client = Marionette(host="127.0.0.1", port=2828, socket_timeout=20)
            try:
                wait_for_marionette(process, profile, log_path)
                client.start_session(timeout=20)
                client.set_context("chrome")
                identity = client.execute_script(
                    'return {locale:Services.locale.appLocaleAsBCP47, platform_version:Services.appinfo.platformVersion, build_id:Services.appinfo.appBuildID};',
                    sandbox=None,
                )
                validate_identity(identity, preflight["firefox_version"])
                report["runtime_identity"] = identity
                client.execute_script(
                    WINDOW + 'w.gBrowser.selectedBrowser.loadURI(Services.io.newURI(arguments[0]), {triggeringPrincipal:Services.scriptSecurityManager.getSystemPrincipal()});',
                    script_args=[FSTEC_URL], sandbox=None,
                )
                eventually(client, WINDOW + r"""
                  const tab = [...w.gBrowser.tabs].find(t =>
                    t.linkedBrowser.currentURI.schemeIs("https") &&
                    t.linkedBrowser.currentURI.asciiHost === "fstec.ru" &&
                    t.linkedBrowser.securityUI?.secInfo?.goodBearTrustDomain === 2);
                  if (!tab) return {ready:false};
                  w.gBrowser.selectedTab = tab;
                  w.gIdentityHandler.refreshIdentityBlock();
                  return {ready:true};
                """, 60)
                validate_ru_state(eventually(client, STATE, 30))
                for theme, addon_id in THEMES.items():
                    applied = client.execute_async_script(
                        r"""
                        const done = arguments[arguments.length-1];
                        const {AddonManager} = ChromeUtils.importESModule("resource://gre/modules/AddonManager.sys.mjs");
                        AddonManager.getAddonByID(arguments[0]).then(async addon => {
                          if (!addon) return done(false);
                          await addon.enable(); done(addon.isActive);
                        }).catch(() => done(false));
                        """, script_args=[addon_id], sandbox=None,
                    )
                    if applied is not True:
                        raise ProbeError(f"Native {theme} theme is unavailable")
                    for scale in (1.0, 1.25):
                        resize_viewport(client, scale)
                        client.actions.sequence("pointer", "mouse").pointer_move(0, 0).perform()
                        client.execute_script(WINDOW + "w.document.activeElement?.blur();", sandbox=None)
                        capture(client, output, report, theme, scale, "default")
                        shield = client.find_element(By.ID, "trust-icon-container")
                        client.actions.sequence("pointer", "mouse").pointer_move(0, 0, origin=shield).perform()
                        capture(client, output, report, theme, scale, "hover")
                        client.actions.sequence("pointer", "mouse").pointer_move(0, 0).perform()
                        client.execute_script(WINDOW + "w.gURLBar.focus();", sandbox=None)
                        for _ in range(30):
                            client.actions.sequence("key", "keyboard").key_down(Keys.SHIFT).key_down(Keys.TAB).key_up(Keys.TAB).key_up(Keys.SHIFT).perform()
                            if client.execute_script(STATE, sandbox=None)["keyboard_focus"]:
                                break
                        capture(client, output, report, theme, scale, "keyboard_focus")
                        shield.click()
                        eventually(client, WINDOW + 'const p=w.document.getElementById("trustpanel-popup");return {ready:p?.state==="open"};', 10)
                        capture(client, output, report, theme, scale, "trust_panel")
                        client.actions.sequence("key", "keyboard").key_down(Keys.ESCAPE).key_up(Keys.ESCAPE).perform()
                if (profile / "cert_override.txt").exists():
                    raise ProbeError("Certificate overrides invalidate capture evidence")
                report["status"] = "captured_manual_review_pending"
                report["runtime_verified"] = True
            except Exception:
                report["status"] = "blocked_capture_incomplete"
                raise
            finally:
                (output / "capture.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/ui/m15-11-156")
    parser.add_argument("--objdir", default="artifacts/development/m15-02-ubuntu-obj")
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--check-prerequisites", action="store_true")
    parser.add_argument("--_inside-mach", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    preflight = prerequisites(args.archive.resolve())
    if args.check_prerequisites or preflight["reasons"]:
        print(json.dumps(preflight, ensure_ascii=False, indent=2))
        return 2 if preflight["reasons"] else 0
    if not args._inside_mach:
        subprocess.run([sys.executable, str(ROOT / "tools/host_build_context.py"),
                        "--objdir", args.objdir, "--intent", "localized-smoke"], check=True)
        script = Path(__file__).resolve()
        child = [str(script), *sys.argv[1:], "--_inside-mach"]
        runner = "import runpy,sys; " + f"sys.path.insert(0,{str(ROOT / 'tools')!r});sys.argv={child!r};runpy.run_path({str(script)!r},run_name='__main__')"
        return subprocess.call([str(SOURCE / "mach"), "python", "-c", runner], cwd=SOURCE)
    try:
        run(args.archive.resolve(), args.output.resolve(), headed=args.headed)
    except Exception as exc:
        print(f"M15-11 capture blocked: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
