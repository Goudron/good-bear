#!/usr/bin/env python3
"""Materialize the pinned Mozilla Russian locale input and Good Bear overlay."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "config" / "firefox-l10n-ru-lock.json"


class L10nError(RuntimeError):
    """The exact Russian locale input cannot safely be reconstructed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise L10nError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative(value: object, label: str) -> Path:
    require(isinstance(value, str) and value and not Path(value).is_absolute(),
            f"{label} must be a nonempty relative path")
    path = Path(value)
    require(".." not in path.parts, f"{label} escapes its root")
    return path


def load_lock(path: Path = LOCK) -> dict[str, Any]:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise L10nError(f"cannot read Russian l10n lock: {exc}") from exc
    require(isinstance(lock, dict) and lock.get("schema_version") == 1,
            "unsupported Russian l10n lock")
    require(lock.get("repository") == "https://github.com/mozilla-l10n/firefox-l10n.git",
            "Russian l10n repository drift")
    revision = lock.get("revision")
    require(isinstance(revision, str) and len(revision) == 40 and
            all(character in "0123456789abcdef" for character in revision),
            "Russian l10n revision is not a Git SHA-1")
    require(lock.get("locale") == "ru", "release locale must be Russian")
    relative(lock.get("checkout"), "l10n checkout")
    relative(lock.get("overlay"), "l10n overlay")
    assets = lock.get("assets")
    require(isinstance(assets, dict) and set(assets) == {
        "ru/browser/browser/aboutDialog.ftl",
        "ru/browser/browser/browser.ftl",
        "ru/browser/browser/goodbearSafeBrowsing.ftl",
        "ru/browser/browser/preferences/goodBearRussianPKI.ftl",
    }, "Russian l10n overlay asset set drift")
    for name, asset in assets.items():
        relative(name, "l10n asset")
        require(isinstance(asset, dict), f"invalid l10n asset: {name}")
        base = asset.get("base_sha256")
        require(base is None or (isinstance(base, str) and len(base) == 64 and
                                 all(character in "0123456789abcdef" for character in base)),
                f"invalid base hash: {name}")
        overlay = asset.get("overlay_sha256")
        require(isinstance(overlay, str) and len(overlay) == 64 and
                all(character in "0123456789abcdef" for character in overlay),
                f"invalid overlay hash: {name}")
    return lock


def git(checkout: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(checkout), *args], check=False,
                            capture_output=True, text=True)
    require(result.returncode == 0, result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def apply_verified_overlay(root: Path, checkout: Path, lock: dict[str, Any]) -> None:
    require(checkout.is_dir(), f"Russian l10n checkout is missing: {checkout}")
    require(git(checkout, "rev-parse", "HEAD") == lock["revision"],
            "Russian l10n checkout revision differs from the pinned lock")
    require(not git(checkout, "status", "--porcelain"),
            "Russian l10n checkout is not clean before applying Good Bear overlay")
    overlay_root = root / relative(lock["overlay"], "l10n overlay")
    for name, asset in lock["assets"].items():
        destination = checkout / relative(name, "l10n asset")
        source = overlay_root / name
        require(source.is_file() and digest(source) == asset["overlay_sha256"],
                f"Good Bear l10n overlay hash mismatch: {name}")
        if asset["base_sha256"] is None:
            require(not destination.exists(), f"pinned l10n unexpectedly already owns: {name}")
        else:
            require(destination.is_file() and digest(destination) == asset["base_sha256"],
                    f"pinned Russian l10n base hash mismatch: {name}")
    for name in lock["assets"]:
        source = overlay_root / name
        destination = checkout / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def verify_materialized_checkout(root: Path, lock: dict[str, Any]) -> Path:
    """Accept only the pinned checkout with precisely the declared overlay."""
    checkout = root / relative(lock["checkout"], "l10n checkout")
    require(checkout.is_dir(), f"Russian l10n checkout is missing: {checkout}")
    require(git(checkout, "rev-parse", "HEAD") == lock["revision"],
            "Russian l10n checkout revision differs from the pinned lock")
    expected_modified = {
        name for name, asset in lock["assets"].items()
        if asset["base_sha256"] is not None
    }
    expected_untracked = set(lock["assets"]) - expected_modified
    modified = {line for line in git(checkout, "diff", "--name-only").splitlines() if line}
    untracked = {
        line for line in git(checkout, "ls-files", "--others", "--exclude-standard").splitlines()
        if line
    }
    require(modified == expected_modified,
            "Russian l10n tracked changes differ from the declared Good Bear overlay")
    require(untracked == expected_untracked,
            "Russian l10n untracked files differ from the declared Good Bear overlay")
    overlay_root = root / relative(lock["overlay"], "l10n overlay")
    for name, asset in lock["assets"].items():
        destination = checkout / relative(name, "l10n asset")
        source = overlay_root / name
        require(source.is_file() and digest(source) == asset["overlay_sha256"],
                f"Good Bear l10n overlay hash mismatch: {name}")
        require(destination.is_file() and digest(destination) == asset["overlay_sha256"],
                f"materialized Russian l10n overlay hash mismatch: {name}")
        base = asset["base_sha256"]
        if base is not None:
            original = subprocess.run(
                ["git", "-C", str(checkout), "show", f"HEAD:{name}"], check=False,
                capture_output=True,
            )
            require(original.returncode == 0 and hashlib.sha256(original.stdout).hexdigest() == base,
                    f"pinned Russian l10n base hash mismatch: {name}")
    return checkout


def materialize(root: Path, lock: dict[str, Any]) -> Path:
    checkout = root / relative(lock["checkout"], "l10n checkout")
    require(not checkout.exists(),
            f"refusing to replace existing Russian l10n checkout: {checkout}")
    checkout.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["git", "init", str(checkout)], check=True)
        git(checkout, "remote", "add", "origin", lock["repository"])
        git(checkout, "sparse-checkout", "init", "--no-cone")
        git(checkout, "sparse-checkout", "set", lock["locale"])
        git(checkout, "fetch", "--depth", "1", "origin", lock["revision"])
        git(checkout, "checkout", "--detach", "FETCH_HEAD")
        apply_verified_overlay(root, checkout, lock)
        return checkout
    except BaseException:
        shutil.rmtree(checkout, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        lock = load_lock(root / "config" / "firefox-l10n-ru-lock.json")
        checkout = materialize(root, lock)
        print(f"Pinned Russian l10n materialized at {checkout}", flush=True)
    except L10nError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
