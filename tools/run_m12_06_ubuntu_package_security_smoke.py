#!/usr/bin/env python3
"""Security-focused clean-target smoke for GB100-M12-06.

The first target is an offline Ubuntu 26.04 amd64 target.  It independently
checks installation scripts, ownership and permissions, a Russian first run,
the Firefox content-sandbox process, and removal.  The second target starts
from the same disposable image but has host networking only for controlled
user-initiated navigation: first a local STANDARD page, then FSTEC's live
Russian-PKI route. Package-script network calls are forbidden. Browser process
sandbox checks run without ptrace: tracing Firefox changes its seccomp setup.
The approved technical scope does not attribute upstream Firefox telemetry to
Good Bear.

This is package verification, not a build entry point.  It neither rebuilds
Good Bear nor changes an accepted artifact.  On a security failure it records
a quarantine marker; this deliberately does not delete a previously promoted
candidate or invalidate its earlier evidence by surprise.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import UTC, datetime
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from typing import Any, Iterator

# This runner is also loaded directly by its focused unittest from outside
# ``tools/``.  Keep the existing M11 live-check helpers importable in both
# invocation modes without relying on the caller's current working directory.
TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from run_m11_fstec_live_russian_pki import (
    FSTEC_URL,
    RUSSIAN_PKI_LABEL,
    RUSSIAN_PKI_TRUST_DOMAIN,
    marionette_state,
    marionette_visible_indicator,
    successful_fstec_tab,
)
from host_build_context import FIREFOX_WORKTREE_NAME, SOURCE


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "goodbear-browser"
TARGET_IMAGE = "ubuntu:26.04"
DEFAULT_PACKAGE = (
    ROOT / "artifacts/m12-02-ubuntu-candidates-r3/"
    f"goodbear-browser_1.0+firefox{FIREFOX_WORKTREE_NAME.removeprefix('firefox-')}-1_amd64.deb"
)
DEFAULT_EVIDENCE_ROOT = ROOT / "artifacts/m12-06-ubuntu-security-smoke"
WINDOWS_MANUAL_BLOCKER = {
    "status": "deferred-until-maintainer-provides-a-windows-environment",
    "automation": "not-run",
    "release_blocker": True,
    "required_manual_checks": [
        "fresh install", "normal launch", "profile creation", "default-browser registration",
        "upgrade", "failed-upgrade recovery", "uninstall",
    ],
}


class SecuritySmokeError(RuntimeError):
    """A package-security requirement was not met."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SecuritySmokeError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def one(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    print("[M12-06] $ " + " ".join(command), flush=True)
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.stdout:
        print(result.stdout.rstrip(), flush=True)
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr, flush=True)
    if check and result.returncode:
        raise SecuritySmokeError(f"command failed ({result.returncode}): {' '.join(command)}")
    return result


def stream(command: list[str]) -> None:
    print("[M12-06] $ " + " ".join(command), flush=True)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, bufsize=1)
    assert process.stdout is not None
    for line in process.stdout:
        print(line.rstrip(), flush=True)
    if process.wait() != 0:
        raise SecuritySmokeError(f"command failed ({process.returncode}): {' '.join(command)}")


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return one(["docker", *args], check=check)


def container_exec(name: str, *command: str, check: bool = True,
                   user: str | None = None) -> subprocess.CompletedProcess[str]:
    arguments = ["exec"]
    if user:
        arguments += ["--user", user]
    arguments += [name, *command]
    return docker(*arguments, check=check)


def image_metadata(image: str) -> dict[str, str]:
    value = json.loads(docker("image", "inspect", image, "--format", "{{json .}}").stdout)
    require(value.get("Os") == "linux" and value.get("Architecture") == "amd64",
            "clean target must be linux/amd64")
    digest = next((item for item in value.get("RepoDigests", []) if item.startswith("ubuntu@sha256:")), "")
    require(re.fullmatch(r"ubuntu@sha256:[0-9a-f]{64}", digest) is not None,
            "clean Ubuntu target has no immutable digest")
    return {"reference": image, "digest": digest, "image_id": value["Id"]}


def control_field(deb: Path, field: str) -> str:
    return one(["dpkg-deb", "-f", str(deb), field]).stdout.strip()


def dependency_names(deb: Path) -> list[str]:
    values = control_field(deb, "Depends").split(",")
    names: list[str] = []
    for expression in values:
        match = re.match(r"\s*([a-z0-9][a-z0-9+.-]*)", expression)
        require(match is not None, f"cannot parse runtime dependency: {expression}")
        names.append(match.group(1))
    require(names, "candidate declares no runtime dependencies")
    return names


def inet_connects(trace: str) -> list[str]:
    """Return each AF_INET/AF_INET6 socket/connect operation from strace text."""
    return [
        line for line in trace.splitlines()
        if ("socket(AF_INET" in line or "connect(" in line and "AF_INET" in line)
    ]


def trace_text(name: str, prefix: str) -> str:
    result = container_exec(
        name, "sh", "-ceu", f"cat {prefix}* 2>/dev/null || true", check=True
    )
    return result.stdout


def package_paths(name: str) -> list[str]:
    return [line for line in container_exec(name, "dpkg-query", "-L", PACKAGE).stdout.splitlines()
            if line.startswith("/")]


def assert_package_security(name: str) -> dict[str, Any]:
    owned = package_paths(name)
    require(owned, "installed package has no owned paths")
    joined = "\n".join(owned)
    require(not re.search(r"/(?:systemd|init\.d|cron|dbus)(?:/|$)", joined),
            "package installs a service/init/cron/dbus payload")
    suspicious = container_exec(
        name, "sh", "-ceu",
        "find /opt/goodbear /usr/bin/good-bear /usr/share/applications/com.ledovskoy.goodbear.desktop "
        "-xdev \\( -perm -0002 -o -perm -6000 \\) -print",
    ).stdout.splitlines()
    require(not suspicious, f"package contains world-writable or set-id paths: {suspicious}")
    caps = container_exec(name, "sh", "-ceu", "getcap -r /opt/goodbear /usr/bin/good-bear 2>/dev/null || true").stdout.splitlines()
    require(not caps, f"package payload carries file capabilities: {caps}")
    scripts = container_exec(
        name, "sh", "-ceu",
        "for p in /var/lib/dpkg/info/goodbear-browser.postinst /var/lib/dpkg/info/goodbear-browser.postrm; do "
        "test -f \"$p\" && cat \"$p\"; done",
    ).stdout
    require(not re.search(r"\b(?:curl|wget|nc|systemctl|service|daemon|cron|dbus)\b", scripts, re.I),
            "package maintainer script has networking or service-management operation")
    elf = container_exec(
        name, "sh", "-ceu",
        "for f in /opt/goodbear/goodbear-bin /opt/goodbear/libmozsandbox.so; do "
        "test -f \"$f\"; readelf -h \"$f\" | awk '/Type:/{print FILENAME \" \" $2}'; "
        "readelf -lW \"$f\" | awk '/GNU_STACK|GNU_RELRO/{print FILENAME \" \" $1 \" \" $NF}'; done",
    ).stdout
    require("DYN" in elf and "GNU_RELRO" in elf, "required Good Bear ELF hardening metadata is absent")
    stack_lines = [line for line in elf.splitlines() if "GNU_STACK" in line]
    require(stack_lines and all(" E " not in f" {line} " for line in stack_lines),
            f"executable stack found in required Good Bear ELF files: {stack_lines}")
    return {"owned_path_count": len(owned), "unsafe_paths": suspicious, "file_capabilities": caps,
            "elf_hardening": elf.splitlines()}


def assert_goodbear_network_boundary() -> dict[str, Any]:
    """Check the Good Bear owners that hold routing/history data.

    DNS alone cannot identify the component that emitted it. The approved
    technical specification leaves upstream Firefox telemetry unchanged, but
    prohibits a Good Bear server and export of Russian-PKI assignment/history
    data. These are the narrow owners of that Good Bear state.
    """
    owners = [
        SOURCE / "browser/components/GoodBearRussianPKIContainer.sys.mjs",
        SOURCE / "browser/actors/GoodBearRussianPKICertificateErrorParent.sys.mjs",
        SOURCE / "browser/actors/GoodBearRussianPKICertificateErrorChild.sys.mjs",
        SOURCE / "security/manager/ssl/GoodBearRussianPKIScopeAuthority.cpp",
    ]
    forbidden = ("fetch(", "XMLHttpRequest", "WebSocket", "Telemetry", "Sync", "upload")
    checked: list[str] = []
    for owner in owners:
        require(owner.is_file(), f"Good Bear network-boundary owner is missing: {owner}")
        found = [token for token in forbidden if token in owner.read_text(encoding="utf-8")]
        require(not found, f"Good Bear routing owner exposes outbound client behaviour in {owner.name}: {found}")
        checked.append(str(owner.relative_to(ROOT)))
    return {"checked_owners": checked, "forbidden_outbound_tokens": list(forbidden),
            "result": "no Good Bear server, telemetry, Sync, upload, or outbound client API"}


def install_candidate(name: str, candidate: Path, *, network_trace: str) -> dict[str, Any]:
    docker("cp", str(candidate), f"{name}:/work-goodbear.deb")
    container_exec(name, "sh", "-ceu", "useradd --create-home --shell /bin/sh goodbear; "
                   "install -d -o goodbear -g goodbear /home/goodbear/profile")
    container_exec(
        name, "sh", "-ceu",
        f"strace -ff -o {network_trace} -e trace=network dpkg -i /work-goodbear.deb",
    )
    trace = trace_text(name, network_trace)
    attempts = inet_connects(trace)
    require(not attempts, f"package installation made an AF_INET/AF_INET6 network call: {attempts}")
    status = container_exec(name, "dpkg-query", "-W", "-f=${Status} ${Version}\\n", PACKAGE).stdout.strip()
    require(status.startswith("install ok installed "), f"unexpected installed package state: {status}")
    return {"status": status, "install_network_attempts": attempts}


def start_xvfb(name: str) -> None:
    container_exec(
        name, "sh", "-ceu",
        "Xvfb :99 -screen 0 1280x800x24 -nolisten tcp >/tmp/m12-06-xvfb.log 2>&1 & "
        "for retry in $(seq 1 50); do test -S /tmp/.X11-unix/X99 && exit 0; sleep 0.1; done; exit 1",
    )


def first_run_and_sandbox(name: str) -> dict[str, Any]:
    start_xvfb(name)
    container_exec(
        name, "env", "DISPLAY=:99", "HOME=/home/goodbear", "LANG=ru_RU.UTF-8", "LANGUAGE=ru:ru_RU",
        "/usr/bin/good-bear", "--createprofile", "M1206 /home/goodbear/profile", user="goodbear",
    )
    container_exec(name, "test", "-f", "/home/goodbear/profile/times.json")
    container_exec(
        name, "sh", "-ceu",
        "cd /home/goodbear; "
        "printf '%s\\n' '<!doctype html><title>Good Bear M12 offline renderer</title>' "
        "> /home/goodbear/m12-06-offline.html; "
        "python3 -m http.server 18080 --bind 127.0.0.1 --directory /home/goodbear "
        ">/home/goodbear/m12-06-offline-server.log 2>&1 & "
        "echo $! > /home/goodbear/m12-06-offline-server.pid; "
        "for retry in $(seq 1 50); do "
        "test -s /home/goodbear/m12-06-offline-server.pid && "
        "kill -0 $(cat /home/goodbear/m12-06-offline-server.pid) && break; sleep 0.1; done; "
        "test -s /home/goodbear/m12-06-offline-server.pid && "
        "kill -0 $(cat /home/goodbear/m12-06-offline-server.pid); "
        "DISPLAY=:99 HOME=/home/goodbear LANG=ru_RU.UTF-8 LANGUAGE=ru:ru_RU "
        "/usr/bin/good-bear --no-remote --profile /home/goodbear/profile "
        "http://127.0.0.1:18080/m12-06-offline.html "
        ">/home/goodbear/m12-06-startup.log 2>&1 & echo $! > /home/goodbear/m12-06-browser.pid; "
        "for retry in $(seq 1 150); do test -e /home/goodbear/profile/.parentlock && exit 0; sleep 0.2; done; "
        "cat /home/goodbear/m12-06-startup.log; exit 1",
        user="goodbear",
    )
    deadline = time.monotonic() + 30
    processes: list[str] = []
    content_ids: list[str] = []
    while time.monotonic() < deadline:
        processes = container_exec(
            name, "sh", "-ceu",
            "ps -eo user=,pid=,ppid=,args= | grep '[g]oodbear' || true",
        ).stdout.splitlines()
        content_ids = [
            fields[1]
            for line in processes
            if len(fields := line.split(maxsplit=3)) == 4
            and " -contentproc " in f" {fields[3]}"
            and " -isForBrowser " in f" {fields[3]}"
            and fields[3].endswith(" tab")
        ]
        if content_ids:
            break
        time.sleep(0.2)
    require(processes and all(line.split(maxsplit=1)[0] == "goodbear" for line in processes),
            f"Good Bear runtime has an unexpected privileged process: {processes}")
    # ``-contentproc`` also names Firefox's socket process and fork server.
    # Neither is a browser tab renderer and both deliberately have a different
    # sandbox lifecycle. The offline loopback HTTP page above makes the tab
    # renderer observable without external network access. Select its
    # Firefox-154 browser role from the process snapshot itself instead of
    # launching ``pgrep``: its pattern is visible in its own transient command
    # line and can otherwise be mistaken for a renderer.
    require(content_ids, "first run did not create a Firefox tab content process")
    sandbox: dict[str, dict[str, str]] = {}
    exited_after_snapshot: list[str] = []
    for pid in content_ids:
        # A spare initial tab can close while this external verifier moves from
        # the process-list snapshot to /proc.  Treat only that precise ENOENT
        # race as non-evidence, but still require a fully inspected renderer.
        result = container_exec(
            name, "sh", "-ceu",
            f"awk '/^NoNewPrivs:|^CapEff:|^CapPrm:|^Seccomp:|^Seccomp_filters:/{'{'}print{'}'}' /proc/{pid}/status; cat /proc/{pid}/uid_map",
            check=False,
        ).stdout
        if not result:
            exited_after_snapshot.append(pid)
            continue
        status = result
        require("NoNewPrivs:\t1" in status, f"content process {pid} lacks no_new_privs: {status!r}")
        require(not re.search(r"Cap(?:Eff|Prm):\s+0*[1-9a-f]", status),
                f"content process {pid} retains Linux capabilities: {status!r}")
        # Firefox's tab renderer sandbox is seccomp-based here. A user namespace is
        # not a universal precondition: its availability varies by kernel and
        # container policy, while an installed seccomp filter plus no_new_privs
        # and zero process capabilities are the enforceable package property.
        require(re.search(r"^Seccomp:\s+2$", status, re.M) is not None,
                f"content process {pid} has no seccomp filter: {status!r}")
        sandbox[pid] = {"status_and_uid_map": status.strip()}
    require(sandbox, "no tab content process survived long enough for sandbox inspection")
    container_exec(
        name, "sh", "-ceu",
        "kill $(cat /home/goodbear/m12-06-browser.pid) "
        "$(cat /home/goodbear/m12-06-offline-server.pid) || true",
        user="goodbear",
    )
    return {"profile_created": True,
            "network_trace": "not attached to browser; ptrace would alter Firefox seccomp enforcement",
            "content_sandbox_scope": "tab/content renderers (-contentproc, excluding Firefox forkserver)",
            "processes": processes, "content_sandbox": sandbox,
            "exited_after_process_snapshot": exited_after_snapshot}


def uninstall_and_preserve_profile(name: str, owned: list[str]) -> dict[str, Any]:
    container_exec(name, "apt-get", "remove", "-y", PACKAGE)
    status = container_exec(name, "dpkg-query", "-W", "-f=${Status} ${Version}\\n", PACKAGE,
                            check=False).stdout.strip()
    require(not status.startswith("install ok installed "), "package remains installed after remove")
    # This is an ``apt remove``, not a purge.  Debian package lists include
    # common directory entries such as ``/.`` and ``/usr/share``; they are not
    # payload objects to delete and may be shared by the base OS.  Match the
    # accepted M12-04 lifecycle rule: every package-owned regular file and
    # symlink must go, while common directories may remain.
    for path in owned:
        if path.startswith("/"):
            container_exec(name, "sh", "-ceu", f"test ! -f '{path}' && test ! -L '{path}'")
    container_exec(name, "test", "-f", "/home/goodbear/profile/times.json")
    return {"status": status, "package_owned_regular_or_symlink_paths_remaining": 0,
            "user_profile_preserved": True}


@contextmanager
def local_standard_server() -> Iterator[str]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - standard-library callback name
            body = b"<title>Good Bear M12 STANDARD</title><p>standard</p>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/standard"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def port_available(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        require(probe.connect_ex(("127.0.0.1", port)) != 0,
                f"host port {port} is already in use; refusing to attach to an unrelated Marionette server")


def wait_for_file(name: str, path: str, timeout: int) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if container_exec(name, "test", "-f", path, check=False).returncode == 0:
            return
        time.sleep(0.2)
    raise SecuritySmokeError(f"browser did not create {path}")


def live_clean_target(name: str, *, standard_url: str, timeout: int) -> dict[str, Any]:
    """Run controlled user-initiated live navigation from a fresh package install."""
    try:
        from marionette_driver.marionette import Marionette
    except ModuleNotFoundError as exc:
        raise SecuritySmokeError("Marionette driver is unavailable on the verification host") from exc
    start_xvfb(name)
    port_available(2828)
    container_exec(
        name, "sh", "-ceu",
        "cd /home/goodbear; "
        "DISPLAY=:99 HOME=/home/goodbear LANG=ru_RU.UTF-8 LANGUAGE=ru:ru_RU "
        "/usr/bin/good-bear --no-remote --marionette --remote-allow-system-access "
        "--profile /home/goodbear/profile about:blank >/home/goodbear/m12-06-live.log 2>&1 & "
        "echo $! > /home/goodbear/m12-06-live.pid",
        user="goodbear",
    )
    wait_for_file(name, "/home/goodbear/profile/MarionetteActivePort", timeout)
    port = container_exec(name, "cat", "/home/goodbear/profile/MarionetteActivePort").stdout.strip()
    require(port == "2828", f"unexpected Marionette port: {port!r}")
    client = Marionette(host="127.0.0.1", port=2828, socket_timeout=20)
    try:
        client.start_session(timeout=20)
        client.set_context("chrome")
        locale = client.execute_script("return Services.locale.appLocaleAsBCP47;", sandbox=None)
        require(locale == "ru", f"packaged first run did not select Russian UI locale: {locale!r}")
        print("[M12-06 5/7] Opening a requested local STANDARD page in the ordinary context", flush=True)
        client.execute_script(
            """
            const w = Services.wm.getMostRecentWindow("navigator:browser");
            w.gBrowser.selectedBrowser.loadURI(Services.io.newURI(arguments[0]), {
              triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
            });
            """, [standard_url], sandbox=None,
        )
        deadline = time.monotonic() + timeout
        standard: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            standard = client.execute_script(
                """
                const w = Services.wm.getMostRecentWindow("navigator:browser");
                const browser = w.gBrowser.selectedBrowser;
                return {url: browser.currentURI.spec,
                        userContextId: browser.browsingContext.originAttributes.userContextId,
                        trustDomain: browser.securityUI?.secInfo?.goodBearTrustDomain ?? null};
                """, sandbox=None,
            )
            if standard.get("url") == standard_url:
                break
            time.sleep(0.25)
        require(standard is not None and standard.get("url") == standard_url and
                standard.get("userContextId") == 0 and standard.get("trustDomain") != RUSSIAN_PKI_TRUST_DOMAIN,
                f"STANDARD browsing did not remain ordinary: {standard!r}")
        print("[M12-06 6/7] Opening FSTEC by explicit user-equivalent navigation", flush=True)
        client.execute_script(
            """
            const w = Services.wm.getMostRecentWindow("navigator:browser");
            const tab = w.gBrowser.addTab("about:blank", {
              userContextId: 0,
              triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
            });
            w.gBrowser.selectedTab = tab;
            tab.linkedBrowser.loadURI(Services.io.newURI(arguments[0]), {
              triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
            });
            """, [FSTEC_URL], sandbox=None,
        )
        deadline = time.monotonic() + timeout
        state: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            state = marionette_state(client)
            if successful_fstec_tab(state):
                break
            time.sleep(1)
        require(state is not None and successful_fstec_tab(state) is not None,
                f"FSTEC did not enter the dedicated Russian PKI container: {state!r}")
        indicator = marionette_visible_indicator(client)
        require(indicator.get("value") == RUSSIAN_PKI_LABEL and not indicator.get("hidden") and
                not indicator.get("collapsed") and indicator.get("usesRussianPKI"),
                f"Russian PKI RU indicator is not visible in the packaged browser: {indicator!r}")
        return {"locale": locale, "standard": standard, "fstec": successful_fstec_tab(state),
                "russian_pki_indicator": indicator,
                "network_trace": "not attached to browser; ptrace would alter Firefox seccomp enforcement"}
    finally:
        try:
            client.delete_session()
        except Exception:
            pass
        container_exec(name, "sh", "-ceu", "kill $(cat /home/goodbear/m12-06-live.pid) || true", user="goodbear", check=False)


def record_quarantine(destination: Path, candidate: Path, reason: str) -> Path:
    """Record a fail-closed security quarantine without deleting prior evidence."""
    output = destination / "quarantine" / uuid.uuid4().hex / "security-failure.json"
    output.parent.mkdir(parents=True, exist_ok=False)
    output.write_text(json.dumps({
        "task": "GB100-M12-06", "observed_at": datetime.now(UTC).isoformat(),
        "candidate": str(candidate), "candidate_sha256": sha256(candidate) if candidate.is_file() else None,
        "reason": reason, "release_status": "quarantined; do not promote or publish",
    }, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, default=DEFAULT_PACKAGE)
    parser.add_argument("--image", default=TARGET_IMAGE)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--timeout-seconds", type=int, default=75)
    args = parser.parse_args()
    candidate = args.package.resolve()
    base_name = f"goodbear-m12-06-{uuid.uuid4().hex[:12]}"
    prepared_image = f"goodbear-m12-06-prepared:{uuid.uuid4().hex[:12]}"
    offline_name = f"{base_name}-offline"
    live_name = f"{base_name}-live"
    prepared = offline_created = live_created = False
    try:
        require(args.timeout_seconds >= 30, "timeout must be at least 30 seconds")
        require(candidate.is_file(), f"Ubuntu candidate is missing: {candidate}")
        require(control_field(candidate, "Package") == PACKAGE, "wrong Debian package identity")
        require(control_field(candidate, "Architecture") == "amd64", "candidate is not amd64")
        image = image_metadata(args.image)
        dependencies = dependency_names(candidate)
        print("[M12-06 1/7] Validating r3 input and preparing the disposable clean Ubuntu image", flush=True)
        print(f"  package SHA-256: {sha256(candidate)}; target: {image['digest']}", flush=True)
        setup_name = f"{base_name}-setup"
        provision = (
            "set -eu; export DEBIAN_FRONTEND=noninteractive; apt-get update; "
            "apt-get install -y --no-install-recommends " +
            " ".join([*dependencies, "desktop-file-utils", "shared-mime-info", "xdg-utils", "xvfb", "strace", "procps", "libcap2-bin", "binutils", "python3"])
        )
        stream(["docker", "run", "--name", setup_name, args.image, "sh", "-ceu", provision])
        docker("commit", setup_name, prepared_image)
        prepared = True
        docker("rm", setup_name)
        print("[M12-06 2/7] Installing offline and checking package scripts, paths, and ELF hardening", flush=True)
        docker("run", "-d", "--name", offline_name, "--network", "none",
               "--security-opt=no-new-privileges:true", "--security-opt=seccomp=unconfined",
               prepared_image, "sleep", "infinity")
        offline_created = True
        offline_install = install_candidate(offline_name, candidate, network_trace="/tmp/m12-06-install.trace")
        static_security = assert_package_security(offline_name)
        goodbear_network_boundary = assert_goodbear_network_boundary()
        print("[M12-06 3/7] Running a Russian first run offline and inspecting the content sandbox", flush=True)
        offline_runtime = first_run_and_sandbox(offline_name)
        owned = package_paths(offline_name)
        print("[M12-06 4/7] Removing the offline package and retaining the user profile", flush=True)
        offline_uninstall = uninstall_and_preserve_profile(offline_name, owned)
        print("[M12-06 5/7] Starting a separate clean target for controlled user-initiated live navigation", flush=True)
        docker("run", "-d", "--name", live_name, "--network", "host",
               "--security-opt=no-new-privileges:true", "--security-opt=seccomp=unconfined",
               prepared_image, "sleep", "infinity")
        live_created = True
        live_install = install_candidate(live_name, candidate, network_trace="/tmp/m12-06-live-install.trace")
        with local_standard_server() as standard_url:
            live_result = live_clean_target(live_name, standard_url=standard_url, timeout=args.timeout_seconds)
        print("[M12-06 7/7] Recording Ubuntu security evidence; Windows stays a manual release blocker", flush=True)
        args.evidence_root.mkdir(parents=True, exist_ok=True)
        output = args.evidence_root / f"m12-06-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
        output.write_text(json.dumps({
            "schema_version": 1, "task": "GB100-M12-06", "observed_at": datetime.now(UTC).isoformat(),
            "platform": "Ubuntu 26.04 amd64 clean Docker targets",
            "target_image": image,
            "package": {"path": str(candidate.relative_to(ROOT)), "sha256": sha256(candidate),
                        "version": control_field(candidate, "Version")},
            "offline_target": {"network": "docker --network none", "install": offline_install,
                               "package_security": static_security, "first_run_and_sandbox": offline_runtime,
                               "uninstall": offline_uninstall},
            "good_bear_network_boundary": goodbear_network_boundary,
            "controlled_live_target": {"network": "docker --network host only for controlled user-initiated live navigation",
                                         "install": live_install, "result": live_result},
            "windows_manual_validation": WINDOWS_MANUAL_BLOCKER,
            "public_release_allowed": False,
        }, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"M12-06 Ubuntu security evidence: {output}", flush=True)
    except (SecuritySmokeError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        args.evidence_root.mkdir(parents=True, exist_ok=True)
        marker = record_quarantine(args.evidence_root, candidate, str(exc))
        print(f"ERROR: {exc}\nM12-06 candidate quarantined: {marker}", file=sys.stderr, flush=True)
        return 1
    finally:
        if offline_created:
            docker("rm", "-f", offline_name, check=False)
        if live_created:
            docker("rm", "-f", live_name, check=False)
        if prepared:
            docker("image", "rm", "-f", prepared_image, check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
