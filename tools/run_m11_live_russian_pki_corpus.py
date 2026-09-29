#!/usr/bin/env python3
"""Probe the opt-in, test-only GB100-M11-06 Russian-PKI live corpus.

The checked-in corpus is only a deduplicated set of public *candidates*.  It
does not configure routing, trust, or a runtime allowlist.  Each invocation
captures a separate timestamped report under ``artifacts/``.  An unavailable
or changed public endpoint is an observation (``unreachable`` or ``stale``),
not a passing result and never a local build/test failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from project_temp import temporary_directory
from host_build_context import FIREFOX_WORKTREE_NAME, ROOT, SOURCE
from verify_russian_release_archive import ArchiveError, verify as verify_archive


FIREFOX_VERSION = FIREFOX_WORKTREE_NAME.removeprefix("firefox-")
CORPUS_PATH = ROOT / "config" / "m11-06-live-russian-pki-corpus.json"
MANIFEST_PATH = ROOT / "config" / "russian-pki-manifest.json"
BUILD_INPUTS = ROOT / "artifacts" / "certificates" / "build-inputs" / "current"
REPORT_DIRECTORY = ROOT / "artifacts" / "live-russian-pki-corpus"
DEFAULT_ARCHIVE = ROOT / "artifacts/development/m15-02-ubuntu-obj/dist" / f"goodbear-1.0+firefox{FIREFOX_VERSION}.ru.linux-x86_64.tar.xz"
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
PEM_CERTIFICATE = re.compile(
    br"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----"
)
RUSSIAN_PKI_TRUST_DOMAIN = 2


class CorpusError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusError(f"cannot read {description}: {exc}") from exc
    if not isinstance(value, dict):
        raise CorpusError(f"{description} must be an object")
    return value


def require_exact_fields(value: dict[str, Any], fields: set[str], description: str) -> None:
    if set(value) != fields:
        raise CorpusError(f"{description} has missing or unknown fields")


def validate_corpus(corpus: dict[str, Any]) -> list[dict[str, str]]:
    require_exact_fields(corpus, {"schema_version", "task", "policy", "candidates"}, "corpus")
    if corpus["schema_version"] != 1 or corpus["task"] != "GB100-M11-06":
        raise CorpusError("unexpected live corpus schema or task")
    policy = corpus["policy"]
    if not isinstance(policy, dict):
        raise CorpusError("corpus policy must be an object")
    expected_policy = {
        "test_only": True,
        "runtime_allowlist": False,
        "production_trust_input": False,
        "external_availability_required": False,
        "government_endpoint_required": False,
        "result_location": "artifacts/live-russian-pki-corpus",
    }
    require_exact_fields(policy, set(expected_policy), "corpus policy")
    if policy != expected_policy:
        raise CorpusError("live corpus policy weakens its test-only boundary")
    candidates = corpus["candidates"]
    if not isinstance(candidates, list) or not candidates:
        raise CorpusError("live corpus needs at least one candidate")
    ids: set[str] = set()
    urls: set[str] = set()
    validated: list[dict[str, str]] = []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            raise CorpusError(f"candidate {index} must be an object")
        require_exact_fields(candidate, {"id", "url", "kind"}, f"candidate {index}")
        identifier = candidate["id"]
        url = candidate["url"]
        kind = candidate["kind"]
        parsed = urlparse(url) if isinstance(url, str) else None
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{2,127}", identifier)
            or not isinstance(kind, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{2,127}", kind)
            or parsed is None
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.port not in {None, 443}
        ):
            raise CorpusError(f"candidate {index} is not a safe HTTPS endpoint")
        normalized = parsed._replace(fragment="").geturl()
        if identifier in ids or normalized in urls:
            raise CorpusError("live corpus candidates must be deduplicated")
        ids.add(identifier)
        urls.add(normalized)
        validated.append({"id": identifier, "url": normalized, "kind": kind})
    return validated


def load_supported_chain_inputs(manifest_path: Path = MANIFEST_PATH) -> dict[str, Any]:
    manifest = load_json(manifest_path, "Russian PKI manifest")
    anchors = manifest.get("trust_anchors")
    intermediates = manifest.get("intermediates")
    if not isinstance(anchors, list) or not isinstance(intermediates, list):
        raise CorpusError("Russian PKI manifest has no reviewed chain inputs")
    anchor_hashes: dict[str, str] = {}
    intermediate_hashes: dict[str, dict[str, str]] = {}
    for role, values, destination in (
        ("trust_anchor", anchors, anchor_hashes),
        ("intermediate", intermediates, intermediate_hashes),
    ):
        for item in values:
            if not isinstance(item, dict) or item.get("role") != role:
                raise CorpusError("Russian PKI manifest role confusion")
            identity = item.get("identity")
            certificate_id = item.get("id")
            digest = identity.get("certificate_der_sha256") if isinstance(identity, dict) else None
            if not isinstance(certificate_id, str) or not isinstance(digest, str) or not HEX_SHA256.fullmatch(digest):
                raise CorpusError("Russian PKI manifest contains an invalid exact identity")
            if role == "trust_anchor":
                destination[digest] = certificate_id
                continue
            parent = item.get("chains_to_anchor_identity")
            parent_digest = (
                parent.get("certificate_der_sha256") if isinstance(parent, dict) else None
            )
            if not isinstance(parent_digest, str) or not HEX_SHA256.fullmatch(parent_digest):
                raise CorpusError("Russian PKI intermediate has no exact root parent")
            destination[digest] = {"id": certificate_id, "root_der_sha256": parent_digest}
    if not anchor_hashes or not intermediate_hashes:
        raise CorpusError("Russian PKI manifest has no active exact chain")
    return {"anchors": anchor_hashes, "intermediates": intermediate_hashes}


def certificate_der(pem: bytes) -> bytes:
    result = subprocess.run(
        ["openssl", "x509", "-outform", "DER"], input=pem, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False
    )
    if result.returncode:
        raise CorpusError(f"OpenSSL could not parse a served certificate: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def fetch_served_certificates(hostname: str, timeout_seconds: int) -> list[bytes]:
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{hostname}:443", "-servername", hostname, "-showcerts"],
            input=b"", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout_seconds, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CorpusError(f"TLS probe could not reach {hostname}: {exc}") from exc
    certificates = [certificate_der(pem) for pem in PEM_CERTIFICATE.findall(result.stdout)]
    if not certificates:
        detail = result.stdout.decode("utf-8", errors="replace").strip().splitlines()[-3:]
        raise CorpusError(f"TLS probe received no certificates from {hostname}: {' | '.join(detail)}")
    return certificates


def platform_ordinary_failure(hostname: str, timeout_seconds: int) -> dict[str, str]:
    """Record the host platform's normal trust result without disabling TLS checks."""
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{hostname}:443", "-servername", hostname,
             "-verify_return_error"],
            input=b"", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout_seconds, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "unreachable", "detail": str(exc)}
    output = result.stdout.decode("utf-8", errors="replace")
    if result.returncode == 0:
        return {"status": "unexpectedly_accepted", "detail": "platform default trust accepted the endpoint"}
    error = next((line.strip() for line in output.splitlines() if "verify error" in line), "normal platform TLS verification rejected the endpoint")
    return {"status": "rejected", "detail": error}


def write_pem(path: Path, der: bytes) -> None:
    result = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-outform", "PEM"], input=der,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode:
        raise CorpusError(f"OpenSSL could not write certificate input {path.name}")
    path.write_bytes(result.stdout)


def verify_exact_chain(
    hostname: str, leaf: bytes, intermediate: bytes, root: bytes, temporary: Path
) -> bool:
    leaf_path = temporary / "leaf.pem"
    intermediate_path = temporary / "intermediate.pem"
    root_path = temporary / "root.pem"
    write_pem(leaf_path, leaf)
    write_pem(intermediate_path, intermediate)
    write_pem(root_path, root)
    verified = subprocess.run(
        ["openssl", "verify", "-verify_hostname", hostname, "-CAfile", str(root_path),
         "-untrusted", str(intermediate_path), str(leaf_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    return verified.returncode == 0


def exact_chain_observation(hostname: str, inputs: dict[str, Any], temporary: Path, timeout_seconds: int) -> dict[str, Any]:
    temporary.mkdir(parents=True, exist_ok=True)
    served = fetch_served_certificates(hostname, timeout_seconds)
    served_hashes = [hashlib.sha256(certificate).hexdigest() for certificate in served]
    leaf = served[0]
    intermediate_pair = next(
        ((certificate, digest) for certificate, digest in zip(served[1:], served_hashes[1:])
         if digest in inputs["intermediates"]),
        None,
    )
    candidates: list[tuple[bytes, str, str]] = []
    if intermediate_pair is not None:
        candidates.append((intermediate_pair[0], intermediate_pair[1], "served"))
    else:
        # A server is permitted to omit an intermediate.  This only remains a
        # supported observation if the existing, exact build input completes
        # hostname validation; it never fetches a certificate at runtime.
        for intermediate_digest, intermediate in inputs["intermediates"].items():
            path = BUILD_INPUTS / "intermediate" / f"{intermediate['id']}.der"
            if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == intermediate_digest:
                candidates.append((path.read_bytes(), intermediate_digest, "reviewed_build_input"))
    for intermediate_bytes, intermediate_digest, intermediate_source in candidates:
        intermediate = inputs["intermediates"][intermediate_digest]
        root_digest = intermediate["root_der_sha256"]
        root_id = inputs["anchors"].get(root_digest)
        if not isinstance(root_id, str):
            continue
        root_path = BUILD_INPUTS / "trust_anchor" / f"{root_id}.der"
        if not root_path.is_file() or hashlib.sha256(root_path.read_bytes()).hexdigest() != root_digest:
            continue
        if verify_exact_chain(hostname, leaf, intermediate_bytes, root_path.read_bytes(), temporary):
            return {
                "leaf_der_sha256": served_hashes[0],
                "intermediate_der_sha256": intermediate_digest,
                "intermediate_id": intermediate["id"],
                "intermediate_source": intermediate_source,
                "root_der_sha256": root_digest,
                "root_id": root_id,
            }
    if intermediate_pair is None:
        raise CorpusError("served leaf could not be completed by any existing exact intermediate")
    raise CorpusError("served chain did not verify to its supported exact root")


def extract_archive(archive: Path, destination: Path) -> Path:
    try:
        with tarfile.open(archive, "r:xz") as bundle:
            bundle.extractall(destination, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise CorpusError(f"cannot extract Russian candidate: {exc}") from exc
    binary = destination / "goodbear" / "goodbear"
    if not binary.is_file():
        raise CorpusError("Good Bear executable is missing from Russian candidate")
    return binary


def wait_for_marionette(process: subprocess.Popen[str], profile: Path, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        active_port = profile / "MarionetteActivePort"
        if active_port.is_file() and active_port.read_text(encoding="ascii").strip() == "2828":
            return
        if process.poll() is not None:
            raise CorpusError("Good Bear exited before Marionette was ready")
        time.sleep(0.2)
    raise CorpusError("Good Bear did not expose Marionette on port 2828")


def navigate_in_fresh_browser(client: Any, url: str, timeout_seconds: int) -> dict[str, Any]:
    client.execute_script(
        f"""
        const w = Services.wm.getMostRecentWindow("navigator:browser");
        w.gBrowser.selectedBrowser.loadURI(Services.io.newURI({url!r}), {{
          triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
        }});
        """, sandbox=None,
    )
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        state = client.execute_script(
            f"""
            const w = Services.wm.getMostRecentWindow("navigator:browser");
            const target = {url!r};
            const tabs = [...w.gBrowser.tabs].map(tab => {{
              const browser = tab.linkedBrowser;
              return {{
                url: browser.currentURI.spec,
                userContextId: browser.browsingContext.originAttributes.userContextId,
                trustDomain: browser.securityUI?.secInfo?.goodBearTrustDomain ?? null,
              }};
            }});
            const isolated = tabs.find(tab => tab.url === target &&
              tab.userContextId > 0 && tab.trustDomain === {RUSSIAN_PKI_TRUST_DOMAIN});
            const ordinaryTrusted = tabs.some(tab => tab.url === target &&
              tab.userContextId === 0 && tab.trustDomain === {RUSSIAN_PKI_TRUST_DOMAIN});
            return {{ready: Boolean(isolated), ordinaryTrusted, tabs}};
            """, sandbox=None,
        )
        if not isinstance(state, dict):
            raise CorpusError("browser returned an invalid navigation state")
        last = state
        if state.get("ready"):
            return state
        time.sleep(1)
    raise CorpusError(f"isolated navigation was not observed before timeout: {last!r}")


def write_report(report: dict[str, Any], output: Path | None) -> Path:
    REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    if output is None:
        timestamp = report["observed_at"].replace(":", "").replace("-", "")
        output = REPORT_DIRECTORY / f"m11-06-{timestamp}.json"
    output = output.resolve()
    if output.parent != REPORT_DIRECTORY.resolve():
        raise CorpusError("live corpus report must stay in artifacts/live-russian-pki-corpus")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent, delete=False) as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(output)
    return output


def run(archive: Path, *, timeout_seconds: int, output: Path | None, headless: bool) -> Path:
    try:
        from marionette_driver.marionette import Marionette
    except ModuleNotFoundError as exc:
        raise CorpusError("Marionette dependencies are unavailable") from exc
    try:
        verify_archive(archive)
    except ArchiveError as exc:
        raise CorpusError(f"Russian-only archive precheck failed: {exc}") from exc
    candidates = validate_corpus(load_json(CORPUS_PATH, "live corpus"))
    inputs = load_supported_chain_inputs()
    report: dict[str, Any] = {
        "schema_version": 1,
        "task": "GB100-M11-06",
        "observed_at": utc_now(),
        "test_only": True,
        "external_availability_required": False,
        "results": [],
    }
    print(f"[M11-06 1/5] Loaded {len(candidates)} deduplicated test-only public candidates", flush=True)
    with temporary_directory(prefix="good-bear-m11-06-") as temporary_name:
        temporary = Path(temporary_name)
        print("[M11-06 2/5] Probing served chains against existing exact manifest roots", flush=True)
        prepared: list[tuple[dict[str, str], dict[str, Any], dict[str, str]]] = []
        for candidate in candidates:
            hostname = urlparse(candidate["url"]).hostname
            assert hostname
            ordinary = platform_ordinary_failure(hostname, timeout_seconds)
            try:
                chain = exact_chain_observation(hostname, inputs, temporary / candidate["id"], timeout_seconds)
            except CorpusError as exc:
                status = "unreachable" if ordinary["status"] == "unreachable" else "stale"
                report["results"].append({**candidate, "observed_at": utc_now(), "status": status,
                    "ordinary_context": {"platform_default_tls": ordinary}, "detail": str(exc)})
                continue
            if ordinary["status"] != "rejected":
                report["results"].append({**candidate, "observed_at": utc_now(), "status": "stale",
                    "ordinary_context": {"platform_default_tls": ordinary}, "chain": chain,
                    "detail": "candidate did not fail normal platform verification"})
                continue
            prepared.append((candidate, chain, ordinary))

        if prepared:
            binary = extract_archive(archive, temporary / "archive")
            profile = temporary / "profile"
            profile.mkdir()
            environment = os.environ | {
                "LANG": "ru_RU.UTF-8", "LANGUAGE": "ru_RU:ru",
                "TMPDIR": str(ROOT / "artifacts/build-tmp"), "TMP": str(ROOT / "artifacts/build-tmp"),
                "TEMP": str(ROOT / "artifacts/build-tmp"),
            }
            command = [str(binary), *( [] if not headless else ["--headless"]), "--no-remote", "--marionette",
                       "--remote-allow-system-access", "--profile", str(profile), "about:blank"]
            print("[M11-06 3/5] Starting fresh Russian Good Bear profile for isolated navigation", flush=True)
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, env=environment)
            client = Marionette(host="127.0.0.1", port=2828, socket_timeout=15)
            try:
                try:
                    wait_for_marionette(process, profile, 30)
                    client.start_session(timeout=20)
                    client.set_context("chrome")
                except (CorpusError, OSError) as exc:
                    # Public candidates are still observations when the fresh
                    # browser cannot establish its Marionette session. Record
                    # every already chain-verified candidate as stale rather
                    # than claiming a network failure or silently dropping a
                    # required artifact report.
                    for candidate, chain, ordinary in prepared:
                        report["results"].append({
                            **candidate,
                            "observed_at": utc_now(),
                            "status": "stale",
                            "ordinary_context": {"platform_default_tls": ordinary},
                            "chain": chain,
                            "browser_session": {"status": "not_proven"},
                            "detail": f"browser session unavailable before navigation: {exc}",
                        })
                    report_path = write_report(report, output)
                    print(
                        f"[M11-06 5/5] Browser session unavailable; recorded "
                        f"supported=0 stale={len(prepared)} unreachable=0 -> {report_path}",
                        flush=True,
                    )
                    return report_path
                if (profile / "cert_override.txt").exists():
                    raise CorpusError("fresh live-corpus profile unexpectedly has certificate overrides")
                print("[M11-06 4/5] Proving ordinary-first rejection and native isolated navigation", flush=True)
                for candidate, chain, ordinary in prepared:
                    try:
                        browser = navigate_in_fresh_browser(client, candidate["url"], timeout_seconds)
                        if browser["ordinaryTrusted"]:
                            raise CorpusError("ordinary context acquired Russian PKI trust")
                        report["results"].append({**candidate, "observed_at": utc_now(), "status": "supported",
                            "ordinary_context": {
                                "platform_default_tls": ordinary,
                                "browser_first_visit": {
                                    "status": "redirected_to_isolated_native_russian_pki",
                                    "ordinary_native_trust": False,
                                },
                            }, "chain": chain,
                            "container_navigation": {"status": "isolated_native_russian_pki", "native_trust_domain": RUSSIAN_PKI_TRUST_DOMAIN}})
                    except CorpusError as exc:
                        report["results"].append({**candidate, "observed_at": utc_now(), "status": "stale",
                            "ordinary_context": {"platform_default_tls": ordinary}, "chain": chain,
                            "container_navigation": {"status": "not_proven"}, "detail": str(exc)})
                if (profile / "cert_override.txt").exists():
                    raise CorpusError("live corpus created a certificate override; report is invalid")
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
    report_path = write_report(report, output)
    counts = {status: sum(result["status"] == status for result in report["results"])
              for status in ("supported", "stale", "unreachable")}
    print(f"[M11-06 5/5] Recorded supported={counts['supported']} stale={counts['stale']} unreachable={counts['unreachable']} -> {report_path}", flush=True)
    return report_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--timeout-seconds", type=int, default=45)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--_inside-mach", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.timeout_seconds < 10:
        parser.error("--timeout-seconds must be at least 10")
    archive = args.archive.resolve()
    if not args._inside_mach:
        script = Path(__file__).resolve()
        child_args = [str(script), "--_inside-mach", "--archive", str(archive), "--timeout-seconds", str(args.timeout_seconds)]
        if args.output:
            child_args.extend(("--output", str(args.output.resolve())))
        if args.headed:
            child_args.append("--headed")
        runner = ("import runpy, sys; " f"sys.path.insert(0, {str(ROOT / 'tools')!r}); "
                  f"sys.argv = {child_args!r}; runpy.run_path({str(script)!r}, run_name='__main__')")
        return subprocess.call([str(SOURCE / "mach"), "python", "-c", runner], cwd=SOURCE)
    try:
        run(archive, timeout_seconds=args.timeout_seconds, output=args.output, headless=not args.headed)
    except CorpusError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
