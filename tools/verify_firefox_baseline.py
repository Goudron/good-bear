#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Verify the immutable Firefox baseline without cloning the source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.request import Request, urlopen

from project_temp import temporary_directory


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "config" / "firefox-baseline.json"
HEX_LENGTHS = {"sha256": 64, "sha512": 128}


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "Good-Bear-baseline-verifier/1"})
    with urlopen(request, timeout=30) as response:
        return response.read()


def run(*args: str) -> str:
    try:
        return subprocess.run(
            args,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout
    except FileNotFoundError as exc:
        raise VerificationError(f"required command is unavailable: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip()
        raise VerificationError(f"command failed: {' '.join(args)}: {detail}") from exc


def load_config(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot load {path}: {exc}") from exc


def verify_static(config: dict) -> None:
    require(config.get("schema_version") == 1, "unsupported schema_version")
    require(config.get("channel") == "release", "baseline must use the release channel")
    version = config.get("version", "")
    require(re.fullmatch(r"[1-9][0-9]*\.[0-9]+(?:\.[0-9]+)?", version) is not None,
            "version is not a fixed stable release")

    vcs = config.get("vcs", {})
    revision = vcs.get("revision", "")
    require(vcs.get("repository") == "https://github.com/mozilla-firefox/firefox.git",
            "VCS repository is not Mozilla's official Firefox repository")
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None,
            "VCS revision must be a full 40-character commit ID")
    expected_tag = f"FIREFOX_{version.replace('.', '_')}_RELEASE"
    require(vcs.get("release_tag") == expected_tag, "release tag does not match version")
    require(revision in vcs.get("version_file_url", ""),
            "version_file_url must be pinned to the exact revision")

    release_root = f"https://archive.mozilla.org/pub/firefox/releases/{version}/"
    source = config.get("source", {})
    require(source.get("archive_url", "").startswith(release_root),
            "source archive is not in the pinned Mozilla release directory")
    require(source.get("archive_url", "").endswith(f"firefox-{version}.source.tar.xz"),
            "source archive filename does not match version")
    require(source.get("detached_signature_url") == source.get("archive_url", "") + ".asc",
            "detached signature URL does not match source archive")
    for algorithm, length in HEX_LENGTHS.items():
        require(re.fullmatch(rf"[0-9a-f]{{{length}}}", source.get(algorithm, "")) is not None,
                f"source {algorithm} is missing or malformed")

    signing = config.get("signing", {})
    require(signing.get("key_url") == release_root + "KEY",
            "signing key must come from the pinned Mozilla release directory")
    for name in ("key_sha256",):
        require(re.fullmatch(r"[0-9a-f]{64}", signing.get(name, "")) is not None,
                f"{name} is missing or malformed")
    for name in ("primary_key_fingerprint", "signing_subkey_fingerprint"):
        require(re.fullmatch(r"[0-9A-F]{40}", signing.get(name, "")) is not None,
                f"{name} is missing or malformed")

    summaries = signing.get("signed_summaries", {})
    for algorithm in HEX_LENGTHS:
        summary = summaries.get(algorithm, {})
        expected_url = release_root + algorithm.upper() + "SUMS"
        require(summary.get("url") == expected_url, f"unexpected {algorithm} summary URL")
        require(summary.get("signature_url") == expected_url + ".asc",
                f"unexpected {algorithm} summary signature URL")
        for name in ("content_sha256", "signature_sha256"):
            require(re.fullmatch(r"[0-9a-f]{64}", summary.get(name, "")) is not None,
                    f"{algorithm} {name} is missing or malformed")

    observation = config.get("release_observation", {})
    require(observation.get("latest_version_at_selection") == version,
            "release observation does not match version")
    support = config.get("security_support", {})
    require(support.get("basis") == "mozilla_current_rapid_release",
            "security support basis must be Mozilla's current rapid release")
    require(support.get("support_state_at_selection") == "current",
            "baseline was not recorded as current at selection")
    require(support.get("authoritative_latest_version_url") ==
            observation.get("product_details_url"),
            "security support and release observation use different authorities")
    require(support.get("security_advisories_url") ==
            "https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/",
            "security advisory authority is not Mozilla")
    require(support.get("rebase_boundary") ==
            "new_latest_firefox_version_or_security_dot_release",
            "security rebase boundary is not explicit")
    require(support.get("action_at_boundary") ==
            "stop_release_and_select_a_new_verified_baseline",
            "rebase boundary must fail closed")


def verify_gpg_signature(home: Path, signature: Path, content: Path,
                         signing_fingerprint: str, primary_fingerprint: str) -> None:
    status = run(
        "gpg", "--batch", "--homedir", str(home), "--status-fd", "1",
        "--verify", str(signature), str(content),
    )
    valid_lines = [line for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    require(len(valid_lines) == 1, f"expected one valid signature for {content.name}")
    fields = valid_lines[0].split()
    require(fields[2] == signing_fingerprint, f"unexpected signer for {content.name}")
    require(fields[-1] == primary_fingerprint, f"unexpected primary key for {content.name}")


def verify_online(config: dict, archive: Path | None, require_current: bool) -> None:
    observation = config["release_observation"]
    versions = json.loads(fetch(observation["product_details_url"]))
    current = versions[observation["latest_version_field"]]
    if require_current:
        require(current == config["version"],
                f"baseline is stale: Mozilla latest is {current}, pin is {config['version']}")
        require(versions[observation["last_release_date_field"]] ==
                observation["last_release_date_at_selection"],
                "Mozilla release date no longer matches the recorded observation")

    vcs = config["vcs"]
    refs = run("git", "ls-remote", "--tags", vcs["repository"],
               f"refs/tags/{vcs['release_tag']}")
    expected_ref = f"{vcs['revision']}\trefs/tags/{vcs['release_tag']}"
    require(expected_ref in refs.splitlines(), "Mozilla release tag does not resolve to pinned commit")
    version_text = fetch(vcs["version_file_url"]).decode("utf-8").strip()
    require(version_text == config["version"], "pinned commit contains a different version")

    signing = config["signing"]
    with temporary_directory(prefix="good-bear-baseline-") as temp:
        temp_path = Path(temp)
        key_data = fetch(signing["key_url"])
        require(sha256(key_data) == signing["key_sha256"], "Mozilla KEY hash mismatch")
        key_path = temp_path / "KEY"
        key_path.write_bytes(key_data)
        key_listing = run("gpg", "--batch", "--show-keys", "--with-colons", str(key_path))
        fingerprints = {line.split(":")[9] for line in key_listing.splitlines()
                        if line.startswith("fpr:")}
        require(signing["primary_key_fingerprint"] in fingerprints,
                "pinned Mozilla primary key is absent")
        require(signing["signing_subkey_fingerprint"] in fingerprints,
                "pinned Mozilla signing subkey is absent")

        gpg_home = temp_path / "gnupg"
        gpg_home.mkdir(mode=0o700)
        run("gpg", "--batch", "--homedir", str(gpg_home), "--import", str(key_path))

        for algorithm, digest_length in HEX_LENGTHS.items():
            summary_config = signing["signed_summaries"][algorithm]
            summary_data = fetch(summary_config["url"])
            signature_data = fetch(summary_config["signature_url"])
            require(sha256(summary_data) == summary_config["content_sha256"],
                    f"{algorithm} summary content hash mismatch")
            require(sha256(signature_data) == summary_config["signature_sha256"],
                    f"{algorithm} summary signature hash mismatch")
            summary_path = temp_path / f"{algorithm}SUMS"
            signature_path = temp_path / f"{algorithm}SUMS.asc"
            summary_path.write_bytes(summary_data)
            signature_path.write_bytes(signature_data)
            verify_gpg_signature(
                gpg_home, signature_path, summary_path,
                signing["signing_subkey_fingerprint"], signing["primary_key_fingerprint"],
            )
            expected_line = f"{config['source'][algorithm]}  {config['source']['archive_path']}"
            require(expected_line in summary_data.decode("utf-8").splitlines(),
                    f"source {algorithm} is absent from signed Mozilla summary")

        if archive is not None:
            require(archive.is_file(), f"source archive not found: {archive}")
            for algorithm in HEX_LENGTHS:
                actual = hash_file(archive, algorithm)
                require(actual == config["source"][algorithm], f"source {algorithm} mismatch")
            detached_path = temp_path / "source.tar.xz.asc"
            detached_path.write_bytes(fetch(config["source"]["detached_signature_url"]))
            verify_gpg_signature(
                gpg_home, detached_path, archive,
                signing["signing_subkey_fingerprint"], signing["primary_key_fingerprint"],
            )


def verify_pinned_archive_offline(config: dict, archive: Path) -> None:
    """Verify a locally supplied pinned archive without network or key retrieval."""
    require(archive.is_file(), f"source archive not found: {archive}")
    for algorithm in HEX_LENGTHS:
        actual = hash_file(archive, algorithm)
        require(actual == config["source"][algorithm], f"source {algorithm} mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--online", action="store_true",
                        help="verify current Mozilla metadata, signatures, tag, and revision")
    parser.add_argument("--require-current", action="store_true",
                        help="fail if Mozilla has superseded this stable baseline")
    parser.add_argument("--archive", type=Path,
                        help="also verify a previously downloaded source archive")
    parser.add_argument("--offline", action="store_true",
                        help="verify static policy and local archive hashes without network access")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        verify_static(config)
        require(not (args.offline and (args.online or args.require_current)),
                "--offline cannot be combined with online freshness checks")
        if args.offline and args.archive is not None:
            verify_pinned_archive_offline(config, args.archive)
        elif args.online or args.archive is not None or args.require_current:
            verify_online(config, args.archive, args.require_current)
    except VerificationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"OK: Firefox {config['version']} release baseline is immutable and verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
