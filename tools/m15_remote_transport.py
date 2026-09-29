#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Fail-closed local-authority transport records for GB100-M15-01.

This tool deliberately has no SSH, WinRM, cloud, or publishing integration.
It prepares a reviewable immutable source bundle and transport plan locally,
and separately verifies a returned result before an atomic local promotion.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import uuid
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "config" / "m15-01-remote-transport.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SECRET_PATH_PARTS = {".git", ".cache", "__pycache__", "artifacts", "quarantine"}
SECRET_SUFFIXES = (".key", ".p12", ".pfx", ".kdb", ".jks")
SECRET_NAMES = {".env", "credentials", "credentials.json", "id_rsa", "id_ed25519"}
SECRET_CONTENT = re.compile(
    rb"-----BEGIN(?: [A-Z0-9 ]+)? PRIVATE KEY-----|"
    rb"github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    rb"AKIA[0-9A-Z]{16}|authorization\s*:\s*bearer\s+\S+",
    re.IGNORECASE,
)
GOOGLE_API_KEY_CONTENT = re.compile(rb"AIza[A-Za-z0-9_-]{35}")
PKI_INPUT_DIR = Path("artifacts/certificates/build-inputs/current")
PKI_MANIFEST_NAME = "pki-input-manifest.json"
PKI_BUNDLE_NAME = "pki-input-bundle.tar"
PKI_TRANSPORT_ARCHIVE_NAME = "pki-input-transport.tar"
PKI_PLAN_NAME = "pki-input-transport-plan.json"
SAFEBROWSING_INPUT = {
    "supplier_contract": "config/m15-12-safebrowsing-build-input.json",
    "delivery": "separate external private file",
    "exact_file_sha256_required": True,
    "verify_before_each_mach_phase": True,
    "include_in_source_bundle": False,
    "include_in_logs": False,
    "embedded_in_browser_binary_by_design": True,
}
RUSSIAN_L10N_ROOT = "source/l10n/firefox-l10n/ru"
# These tables own the visible app menu and the connection/security panels.
# They must be real Fluent resources, not the zero-byte placeholders created
# by a partial l10n base on a remote builder.
REQUIRED_RUSSIAN_L10N = frozenset({
    "source/l10n/firefox-l10n/ru/browser/browser/appmenu.ftl",
    "source/l10n/firefox-l10n/ru/browser/browser/browser.ftl",
    "source/l10n/firefox-l10n/ru/browser/browser/protectionsPanel.ftl",
    "source/l10n/firefox-l10n/ru/browser/browser/sitePermissions.ftl",
})


class TransportError(RuntimeError):
    """The source authority must not promote this transport record."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TransportError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TransportError(f"не удалось прочитать {label}: {exc}") from exc
    require(isinstance(value, dict), f"{label}: ожидается JSON-объект")
    return value


def require_clean_git_source(root: Path) -> str:
    """Bind a transport bundle to one committed, clean local source authority."""
    inside = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
        check=False,
        capture_output=True,
        text=True,
    )
    require(inside.returncode == 0 and inside.stdout.strip() == "true",
            "source freeze requires a Git work tree")
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    commit = head.stdout.strip()
    require(head.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
            "source freeze requires an existing Git commit")
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
        check=False,
        capture_output=True,
        text=True,
    )
    require(status.returncode == 0, "source freeze cannot read Git status")
    require(not status.stdout.strip(),
            "source freeze requires a clean Git work tree; commit or remove every local change first")
    return commit


def resolve_relative(root: Path, value: object, label: str) -> Path:
    require(isinstance(value, str) and value and not Path(value).is_absolute(),
            f"{label}: нужен непустой относительный путь")
    candidate = (root / value).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise TransportError(f"{label}: путь выходит за пределы проекта") from exc
    return candidate


def require_relative_path(value: object, label: str) -> Path:
    """Return a normalized archive-relative path, never a host path."""
    require(isinstance(value, str) and value and not Path(value).is_absolute(),
            f"{label}: нужен непустой относительный путь")
    path = Path(value)
    require(".." not in path.parts and path.as_posix() == value,
            f"{label}: недопустимый относительный путь")
    return path


def validate_destination(destination: Path) -> Path:
    destination = destination.resolve()
    forbidden = {ROOT / "artifacts", ROOT / "source" / "quarantine"}
    require(destination not in forbidden and not any(parent in forbidden for parent in destination.parents),
            "для M15-01 укажите новый выделенный каталог вне artifacts и прежних quarantine")
    return destination


def path_is_secret(relative: str) -> bool:
    parts = Path(relative).parts
    name = Path(relative).name.lower()
    return (any(part.lower() in SECRET_PATH_PARTS or part.lower().startswith("obj-") for part in parts)
            or name in SECRET_NAMES or name.endswith(SECRET_SUFFIXES)
            or name.startswith(".env."))


def require_not_secret(path: Path, relative: str, *, allow_browser_api_key: bool = False) -> None:
    require(not path_is_secret(relative), f"секретный или локальный путь запрещён: {relative}")
    try:
        with path.open("rb") as source:
            overlap = b""
            for block in iter(lambda: source.read(1024 * 1024), b""):
                inspected = overlap + block
                require(SECRET_CONTENT.search(inspected) is None and
                        (allow_browser_api_key or GOOGLE_API_KEY_CONTENT.search(inspected) is None),
                        f"обнаружен секрет в передаваемом файле: {relative}")
                # Retain every fixed key prefix across a chunk boundary. The
                # Google key is 39 bytes; never let a split hide it in a log.
                overlap = inspected[-256:]
    except OSError as exc:
        raise TransportError(f"не удалось прочитать {relative}: {exc}") from exc


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    contract = load_json(path, "контракт M15-01")
    require(contract.get("schema_version") == 1 and contract.get("task") == "GB100-M15-01",
            "неподдерживаемый контракт M15-01")
    authority = contract.get("source_authority")
    require(isinstance(authority, dict) and authority.get("remote_connections") == "не реализуются этим инструментом",
            "контракт не должен реализовывать удалённое подключение")
    inputs = contract.get("source_inputs")
    require(isinstance(inputs, dict) and inputs.get("upstream_archive_from_baseline") is True,
            "источник upstream archive должен определяться baseline-конфигурацией")
    paths = inputs.get("declared_paths")
    require(isinstance(paths, list) and paths and all(isinstance(item, str) for item in paths),
            "контракт должен объявлять точные локальные входы")
    build_inputs = contract.get("remote_build_inputs")
    require(isinstance(build_inputs, dict) and set(build_inputs) == {"russian_pki", "safebrowsing"},
            "контракт должен объявлять отдельные Russian PKI и Safe Browsing build inputs")
    require(build_inputs["safebrowsing"] == SAFEBROWSING_INPUT,
            "контракт отдельного private Safe Browsing input изменён или неполон")
    russian_pki = build_inputs["russian_pki"]
    require(isinstance(russian_pki, dict) and russian_pki == {
        "separate_hash_manifest_transport": True,
        "logical_destination": PKI_INPUT_DIR.as_posix(),
        "m3_supply_chain_verifier": "tools/verify_m3_04_certificate_supply_chain.py",
        "verify_before_build_environment": True,
    }, "контракт Russian PKI build input изменён или неполон")
    workspaces = contract.get("remote_workspaces")
    require(isinstance(workspaces, dict) and set(workspaces) == {"ubuntu-amd64", "windows-x64"},
            "нужны отдельные Ubuntu и Windows workspaces")
    for platform, workspace in workspaces.items():
        require(isinstance(workspace, dict) and isinstance(workspace.get("bootstrap_invocations"), list)
                and all(isinstance(command, list) and command
                        and all(isinstance(arg, str) and arg for arg in command)
                        for command in workspace["bootstrap_invocations"])
                and isinstance(workspace.get("build_invocation"), list)
                and workspace["build_invocation"] and all(isinstance(arg, str) and arg for arg in workspace["build_invocation"]),
                f"{platform}: bootstrap или build invocation отсутствует")
    returned = contract.get("returned_result")
    require(isinstance(returned, dict) and returned.get("required_result_file") == "result.json"
            and returned.get("required_prefixes") == ["artifacts/", "logs/"],
            "контракт возврата должен требовать только объявленные artifacts и logs")
    return contract


def series_files(root: Path, relative: str) -> list[Path]:
    series = resolve_relative(root, relative, "patch series")
    require(series.is_file(), "patch series отсутствует")
    files = [series]
    names: set[str] = set()
    for number, raw in enumerate(series.read_text(encoding="utf-8").splitlines(), 1):
        item = raw.strip()
        if not item or item.startswith("#"):
            continue
        require(item.endswith(".patch") and item not in names,
                f"patch series:{number}: недопустимая запись")
        patch = resolve_relative(series.parent, item, f"patch series:{number}")
        require(patch.is_file(), f"patch series:{number}: отсутствует {item}")
        names.add(item)
        files.append(patch)
    return files


def files_below(root: Path, entry: str) -> Iterable[Path]:
    path = resolve_relative(root, entry, "объявленный вход")
    require(path.exists() and not path.is_symlink(), f"объявленный вход отсутствует: {entry}")
    if path.is_file():
        yield path
        return
    for candidate in sorted(path.rglob("*")):
        relative = candidate.relative_to(root).as_posix()
        # Generated interpreter/build state is neither an input nor evidence of
        # one.  It is skipped before any bundle membership decision; a secret
        # in an otherwise declared source/config file still fails below.
        if any(part.lower() in {".git", ".cache", "__pycache__", "artifacts", "quarantine"}
               or part.lower().startswith("obj-") for part in Path(relative).parts):
            continue
        require(not candidate.is_symlink(), f"символическая ссылка запрещена: {candidate.relative_to(root)}")
        if candidate.is_file():
            yield candidate


def declared_files(root: Path, contract: dict[str, Any]) -> tuple[list[Path], dict[str, str]]:
    inputs = contract["source_inputs"]
    baseline_path = resolve_relative(root, inputs["baseline"], "baseline")
    baseline = load_json(baseline_path, "baseline")
    source = baseline.get("source")
    require(isinstance(source, dict), "baseline: отсутствует source")
    archive = resolve_relative(root, source.get("archive_path"), "archive_path из baseline")
    expected = source.get("sha256")
    require(isinstance(expected, str) and SHA256_RE.fullmatch(expected), "baseline: неверный SHA-256 архива")
    require(archive.is_file() and sha256_file(archive) == expected,
            "локальный upstream archive отсутствует или не совпадает с baseline")
    require(RUSSIAN_L10N_ROOT in inputs["declared_paths"],
            "remote source contract must transfer the complete Russian l10n tree")
    l10n_lock = root / "config/firefox-l10n-ru-lock.json"
    if l10n_lock.is_file():
        try:
            try:
                from tools.materialize_pinned_russian_l10n import (
                    L10nError, load_lock, verify_materialized_checkout,
                )
            except ModuleNotFoundError:  # Direct execution from tools/.
                from materialize_pinned_russian_l10n import (
                    L10nError, load_lock, verify_materialized_checkout,
                )
            verify_materialized_checkout(root, load_lock(l10n_lock))
        except L10nError as exc:
            raise TransportError(f"Russian l10n reproducibility gate failed: {exc}") from exc
    found: dict[str, Path] = {}
    for entry in inputs["declared_paths"]:
        for path in files_below(root, entry):
            relative = path.relative_to(root).as_posix()
            found[relative] = path
    for path in series_files(root, inputs["ordered_patch_series"]):
        found[path.relative_to(root).as_posix()] = path
    found[archive.relative_to(root).as_posix()] = archive
    require(found, "контракт не определил ни одного входа")
    missing_l10n = REQUIRED_RUSSIAN_L10N - set(found)
    require(not missing_l10n,
            f"remote source contract misses required Russian Fluent resources: {sorted(missing_l10n)}")
    empty_l10n = sorted(relative for relative in REQUIRED_RUSSIAN_L10N
                        if found[relative].stat().st_size == 0)
    require(not empty_l10n,
            f"remote source contract has empty Russian Fluent resources: {empty_l10n}")
    for relative, path in found.items():
        require_not_secret(path, relative)
    upstream = {
        "product": baseline.get("product"),
        "version": baseline.get("version"),
        "revision": baseline.get("vcs", {}).get("revision"),
        "archive": archive.relative_to(root).as_posix(),
        "archive_sha256": expected,
    }
    require(all(isinstance(value, str) and value for value in upstream.values()),
            "baseline: не хватает product/version/revision/source archive")
    return [found[key] for key in sorted(found)], upstream


def manifest_for(root: Path, contract_path: Path, contract: dict[str, Any]) -> dict[str, Any]:
    source_commit = require_clean_git_source(root)
    files, upstream = declared_files(root, contract)
    entries = [
        {"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path), "size": path.stat().st_size}
        for path in files
    ]
    supplier_path = SAFEBROWSING_INPUT["supplier_contract"]
    supplier_entry = next((item for item in entries if item["path"] == supplier_path), None)
    require(supplier_entry is not None, "source manifest lacks the public Safe Browsing supplier contract")
    supplier = load_json(resolve_relative(root, supplier_path, "supplier contract"), "supplier contract")
    private_inputs = supplier_binding(supplier, supplier_entry["sha256"])
    inputs_digest = hashlib.sha256(
        "".join(f"{item['sha256']}  {item['path']}\n" for item in entries).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": 1,
        "task": "GB100-M15-01",
        "source_authority": "local",
        "source_commit": source_commit,
        "contract": contract_path.relative_to(root).as_posix(),
        "contract_sha256": sha256_file(contract_path),
        "upstream": upstream,
        "declared_inputs_sha256": inputs_digest,
        "declared_inputs": entries,
        "private_build_inputs": private_inputs,
    }


def supplier_binding(supplier: dict[str, Any], contract_sha256: str) -> dict[str, Any]:
    require(supplier.get("schema_version") == 1 and supplier.get("task") == "GB100-M15-12"
            and supplier.get("supplier") == "Google Safe Browsing"
            and isinstance(supplier.get("key_file_sha256"), str)
            and SHA256_RE.fullmatch(supplier["key_file_sha256"])
            and supplier.get("allowed_api_services") == ["safebrowsing.googleapis.com"]
            and supplier.get("key_value_in_source") is False
            and supplier.get("key_value_in_build_logs") is False
            and supplier.get("key_embedded_in_browser_binary_by_design") is True,
            "Safe Browsing supplier binding is absent or unsafe")
    return {"safebrowsing": {
        "supplier_contract": SAFEBROWSING_INPUT["supplier_contract"],
        "supplier_contract_sha256": contract_sha256,
        "key_file_sha256": supplier["key_file_sha256"],
        "delivery": SAFEBROWSING_INPUT["delivery"],
    }}


def write_bundle(bundle: Path, manifest_bytes: bytes, root: Path, manifest: dict[str, Any]) -> None:
    with tarfile.open(bundle, "w") as archive:
        info = tarfile.TarInfo("source-manifest.json")
        info.size = len(manifest_bytes)
        info.mode = 0o644
        info.mtime = 0
        archive.addfile(info, io.BytesIO(manifest_bytes))
        for item in manifest["declared_inputs"]:
            source = resolve_relative(root, item["path"], "manifest input")
            info = tarfile.TarInfo("source/" + item["path"])
            info.size = source.stat().st_size
            info.mode = source.stat().st_mode & 0o777
            info.mtime = 0
            with source.open("rb") as content:
                archive.addfile(info, content)


def plan_for(contract: dict[str, Any], manifest_sha: str, bundle_sha: str,
             private_inputs: dict[str, Any]) -> dict[str, Any]:
    plans: dict[str, Any] = {}
    for platform, workspace in contract["remote_workspaces"].items():
        plans[platform] = {
            "workspace_kind": workspace["kind"],
            "source_manifest_sha256": manifest_sha,
            "source_bundle_sha256": bundle_sha,
            "remote_commands": [
                {"operation": "verify-source", "argv": [
                    "m15_remote_transport.py", "verify-bundle",
                    "--expected-manifest-sha256", manifest_sha,
                    "--expected-bundle-sha256", bundle_sha,
                ],
                 "source_manifest_sha256": manifest_sha, "source_bundle_sha256": bundle_sha},
                *[
                    {"operation": "bootstrap", "argv": invocation,
                     "source_manifest_sha256": manifest_sha, "source_bundle_sha256": bundle_sha}
                    for invocation in workspace["bootstrap_invocations"]
                ],
                {"operation": "build", "argv": workspace["build_invocation"],
                 "source_manifest_sha256": manifest_sha, "source_bundle_sha256": bundle_sha},
                {"operation": "return", "argv": ["return", "result.json", "artifacts/", "logs/"],
                 "source_manifest_sha256": manifest_sha, "source_bundle_sha256": bundle_sha},
            ],
        }
    return {
        "schema_version": 1,
        "task": "GB100-M15-01",
        "mode": "local preparation only; remote credentials and connections are absent",
        "source_manifest": "source-manifest.json",
        "source_manifest_sha256": manifest_sha,
        "source_bundle": "source-bundle.tar",
        "source_bundle_sha256": bundle_sha,
        "private_build_inputs": private_inputs,
        "platforms": plans,
    }


def verify_bundle(root: Path, manifest_path: Path, bundle_path: Path,
                  expected_bundle_sha: str | None = None,
                  expected_manifest_sha: str | None = None) -> dict[str, Any]:
    manifest_bytes = manifest_path.read_bytes()
    manifest = load_json(manifest_path, "source manifest")
    require(manifest.get("task") == "GB100-M15-01", "source manifest другого задания")
    require(isinstance(manifest.get("source_commit"), str) and
            re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"]) is not None,
            "source manifest lacks a committed local source freeze")
    if expected_manifest_sha is not None:
        require(hashlib.sha256(manifest_bytes).hexdigest() == expected_manifest_sha,
                "хеш source manifest не совпадает")
    if expected_bundle_sha is not None:
        require(sha256_file(bundle_path) == expected_bundle_sha, "хеш source bundle не совпадает")
    expected_names = {"source-manifest.json"}
    expected_content = {"source-manifest.json": manifest_bytes}
    for item in manifest.get("declared_inputs", []):
        require(isinstance(item, dict) and isinstance(item.get("path"), str) and SHA256_RE.fullmatch(item.get("sha256", "")),
                "source manifest содержит неверный вход")
        require(not path_is_secret(item["path"]), f"source manifest содержит запрещённый путь: {item['path']}")
        expected_names.add("source/" + item["path"])
    try:
        with tarfile.open(bundle_path, "r") as archive:
            members = archive.getmembers()
            names = {member.name for member in members}
            require(names == expected_names, "bundle содержит необъявленный или отсутствующий вход")
            for member in members:
                require(member.isfile() and not member.issym(), f"bundle содержит недопустимый объект: {member.name}")
                content = archive.extractfile(member)
                require(content is not None, f"bundle: не удалось прочитать {member.name}")
                data = content.read()
                if member.name == "source-manifest.json":
                    require(data == expected_content[member.name], "manifest в bundle не совпадает с переданным")
                    continue
                item = next(value for value in manifest["declared_inputs"] if "source/" + value["path"] == member.name)
                require(hashlib.sha256(data).hexdigest() == item["sha256"],
                        f"bundle: хеш входа не совпадает: {item['path']}")
                if item["path"] == SAFEBROWSING_INPUT["supplier_contract"]:
                    try:
                        supplier = json.loads(data)
                    except (ValueError, UnicodeError):
                        raise TransportError("invalid bundled Safe Browsing supplier contract") from None
                    require(isinstance(supplier, dict), "invalid bundled supplier object")
                    require(manifest.get("private_build_inputs") == supplier_binding(supplier, item["sha256"]),
                            "private input binding differs from bundled supplier contract")
                require(SECRET_CONTENT.search(data) is None and GOOGLE_API_KEY_CONTENT.search(data) is None,
                        f"bundle: обнаружен секрет: {item['path']}")
    except (OSError, tarfile.TarError) as exc:
        raise TransportError(f"не удалось проверить source bundle: {exc}") from exc
    return manifest


def load_m3_supply_chain_verifier(root: Path) -> Any:
    """Load the checked-in M3 verifier from the exact source authority root."""
    verifier = root / "tools" / "verify_m3_04_certificate_supply_chain.py"
    require(verifier.is_file(), "M3-04 supply-chain verifier отсутствует в source authority")
    spec = __import__("importlib.util").util.spec_from_file_location(
        f"good_bear_m15_m3_04_{uuid.uuid4().hex}", verifier
    )
    require(spec is not None and spec.loader is not None,
            "не удалось загрузить M3-04 supply-chain verifier")
    module = __import__("importlib.util").util.module_from_spec(spec)
    # This loader is invoked by the remote engine under `python -I -S -B`.
    # `spec_from_file_location` does not add the verifier's sibling modules to
    # sys.path, so expose only the exact checked-in tools directory while its
    # imports run.  Never inherit an arbitrary caller search path.
    tools_directory = str(verifier.parent.resolve())
    inserted = tools_directory not in sys.path
    if inserted:
        sys.path.insert(0, tools_directory)
    try:
        spec.loader.exec_module(module)
    finally:
        if inserted:
            sys.path.remove(tools_directory)
    return module


def verify_m3_build_inputs(root: Path, build_input_dir: Path) -> None:
    """Run the production M3 gate, never a weaker transport-only substitute."""
    try:
        load_m3_supply_chain_verifier(root).run(build_input_dir)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        raise TransportError(f"M3-04 supply-chain verification failed: {exc}") from exc


def pki_input_source(root: Path) -> Path:
    """Resolve the promoted input generation while keeping it inside the project."""
    logical = root / PKI_INPUT_DIR
    require(logical.is_dir(), "отсутствуют promoted M3 Russian PKI build inputs")
    resolved = logical.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise TransportError("M3 Russian PKI build inputs выходят за пределы проекта") from exc
    require(resolved.is_dir() and not resolved.is_symlink(),
            "M3 Russian PKI build inputs должны разрешаться в реальный каталог")
    return resolved


def pki_files(root: Path) -> list[Path]:
    """Return only regular, reviewed PKI inputs after the full M3 validation."""
    source = pki_input_source(root)
    verify_m3_build_inputs(root, source)
    files: list[Path] = []
    for candidate in sorted(source.rglob("*")):
        require(not candidate.is_symlink(),
                f"M3 Russian PKI input contains forbidden symlink: {candidate.relative_to(source)}")
        require(candidate.is_file() or candidate.is_dir(),
                f"M3 Russian PKI input contains non-regular object: {candidate.relative_to(source)}")
        if candidate.is_file():
            files.append(candidate)
    require(files, "M3 Russian PKI input is empty")
    return files


def pki_manifest_for(root: Path, source_manifest_sha: str, source_bundle_sha: str) -> dict[str, Any]:
    source = pki_input_source(root)
    files = pki_files(root)
    index = load_json(source / "build-inputs.json", "M3 promoted build-inputs index")
    entries = [
        {
            "path": path.relative_to(source).as_posix(),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        }
        for path in files
    ]
    return {
        "schema_version": 1,
        "task": "GB100-M15-01",
        "kind": "verified-russian-pki-build-inputs",
        "source_manifest_sha256": source_manifest_sha,
        "source_bundle_sha256": source_bundle_sha,
        "destination": PKI_INPUT_DIR.as_posix(),
        "m3_supply_chain": {
            "verifier": "tools/verify_m3_04_certificate_supply_chain.py",
            "source_contract_sha256": index.get("source_contract_sha256"),
        },
        "inputs": entries,
    }


def write_pki_bundle(bundle: Path, manifest_bytes: bytes, root: Path,
                     manifest: dict[str, Any]) -> None:
    source = pki_input_source(root)
    with tarfile.open(bundle, "w") as archive:
        info = tarfile.TarInfo(PKI_MANIFEST_NAME)
        info.size = len(manifest_bytes)
        info.mode = 0o644
        info.mtime = 0
        archive.addfile(info, io.BytesIO(manifest_bytes))
        for item in manifest["inputs"]:
            relative = require_relative_path(item["path"], "PKI manifest input")
            input_path = source / relative
            require(input_path.is_file() and not input_path.is_symlink(),
                    f"PKI input disappeared or became unsafe: {relative}")
            info = tarfile.TarInfo("pki/" + relative.as_posix())
            info.size = input_path.stat().st_size
            info.mode = 0o644
            info.mtime = 0
            with input_path.open("rb") as content:
                archive.addfile(info, content)


def write_pki_transport_archive(destination: Path) -> Path:
    """Create the one-file external PKI payload from all verified records."""
    archive_path = destination / PKI_TRANSPORT_ARCHIVE_NAME
    inputs = [
        (PKI_MANIFEST_NAME, destination / PKI_MANIFEST_NAME),
        (PKI_BUNDLE_NAME, destination / PKI_BUNDLE_NAME),
        (PKI_PLAN_NAME, destination / PKI_PLAN_NAME),
    ]
    require(not archive_path.exists() and not archive_path.is_symlink(),
            "refusing to replace an existing PKI transport archive")
    with tarfile.open(archive_path, "w") as archive:
        for name, source in inputs:
            require(source.is_file() and not source.is_symlink(),
                    f"PKI transport input is absent or unsafe: {name}")
            info = tarfile.TarInfo(name)
            info.size = source.stat().st_size
            info.mode = 0o644
            info.mtime = 0
            with source.open("rb") as content:
                archive.addfile(info, content)
    return archive_path


def verify_pki_transport_archive(destination: Path) -> None:
    """Refuse a ciphertext payload that omits or replaces a PKI transport record."""
    inputs = {
        PKI_MANIFEST_NAME: destination / PKI_MANIFEST_NAME,
        PKI_BUNDLE_NAME: destination / PKI_BUNDLE_NAME,
        PKI_PLAN_NAME: destination / PKI_PLAN_NAME,
    }
    archive_path = destination / PKI_TRANSPORT_ARCHIVE_NAME
    require(archive_path.is_file() and not archive_path.is_symlink(),
            "PKI transport archive is absent or unsafe")
    try:
        with tarfile.open(archive_path, "r") as archive:
            members = archive.getmembers()
            require({member.name for member in members} == set(inputs),
                    "PKI transport archive has missing or unknown records")
            for member in members:
                require(member.isfile() and not member.issym() and not member.islnk(),
                        f"PKI transport archive contains forbidden object: {member.name}")
                content = archive.extractfile(member)
                require(content is not None and content.read() == inputs[member.name].read_bytes(),
                        f"PKI transport archive record differs: {member.name}")
    except (OSError, tarfile.TarError) as exc:
        raise TransportError(f"cannot verify PKI transport archive: {exc}") from exc


def pki_plan_for(source_manifest_sha: str, source_bundle_sha: str,
                 pki_manifest_sha: str, pki_bundle_sha: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "task": "GB100-M15-01",
        "kind": "verified-russian-pki-input-transport",
        "source_manifest": "source-manifest.json",
        "source_manifest_sha256": source_manifest_sha,
        "source_bundle": "source-bundle.tar",
        "source_bundle_sha256": source_bundle_sha,
        "pki_manifest": PKI_MANIFEST_NAME,
        "pki_manifest_sha256": pki_manifest_sha,
        "pki_bundle": PKI_BUNDLE_NAME,
        "pki_bundle_sha256": pki_bundle_sha,
    }


def validate_pki_manifest(manifest: dict[str, Any]) -> None:
    required = {
        "schema_version", "task", "kind", "source_manifest_sha256", "source_bundle_sha256",
        "destination", "m3_supply_chain", "inputs",
    }
    require(set(manifest) == required, "PKI manifest has missing or unknown fields")
    require(manifest["schema_version"] == 1 and manifest["task"] == "GB100-M15-01" and
            manifest["kind"] == "verified-russian-pki-build-inputs",
            "unsupported PKI manifest")
    require(SHA256_RE.fullmatch(manifest["source_manifest_sha256"]) and
            SHA256_RE.fullmatch(manifest["source_bundle_sha256"]),
            "PKI manifest has invalid source binding")
    require(manifest["destination"] == PKI_INPUT_DIR.as_posix(),
            "PKI manifest has unexpected build-input destination")
    chain = manifest["m3_supply_chain"]
    require(isinstance(chain, dict) and set(chain) == {"verifier", "source_contract_sha256"} and
            chain["verifier"] == "tools/verify_m3_04_certificate_supply_chain.py" and
            isinstance(chain["source_contract_sha256"], str) and SHA256_RE.fullmatch(chain["source_contract_sha256"]),
            "PKI manifest has invalid M3 supply-chain binding")
    inputs = manifest["inputs"]
    require(isinstance(inputs, list) and inputs, "PKI manifest has no inputs")
    names: set[str] = set()
    for item in inputs:
        require(isinstance(item, dict) and set(item) == {"path", "sha256", "size"},
                "PKI manifest has invalid input entry")
        relative = require_relative_path(item["path"], "PKI manifest input")
        require(relative.as_posix() not in names and SHA256_RE.fullmatch(item["sha256"]) and
                isinstance(item["size"], int) and item["size"] >= 0,
                "PKI manifest has duplicate or invalid input")
        names.add(relative.as_posix())


def verify_pki_bundle(root: Path, pki_manifest_path: Path, pki_bundle_path: Path,
                      source_manifest_path: Path, source_bundle_path: Path,
                      plan: dict[str, Any]) -> dict[str, Any]:
    required_plan = {
        "schema_version", "task", "kind", "source_manifest", "source_manifest_sha256",
        "source_bundle", "source_bundle_sha256", "pki_manifest", "pki_manifest_sha256",
        "pki_bundle", "pki_bundle_sha256",
    }
    require(set(plan) == required_plan and plan.get("schema_version") == 1 and
            plan.get("task") == "GB100-M15-01" and
            plan.get("kind") == "verified-russian-pki-input-transport" and
            plan.get("source_manifest") == "source-manifest.json" and
            plan.get("source_bundle") == "source-bundle.tar" and
            plan.get("pki_manifest") == PKI_MANIFEST_NAME and
            plan.get("pki_bundle") == PKI_BUNDLE_NAME,
            "invalid PKI transport plan")
    for field in ("source_manifest_sha256", "source_bundle_sha256", "pki_manifest_sha256", "pki_bundle_sha256"):
        require(isinstance(plan.get(field), str) and SHA256_RE.fullmatch(plan[field]),
                f"PKI transport plan has invalid {field}")
    require(sha256_file(pki_manifest_path) == plan["pki_manifest_sha256"],
            "PKI manifest hash mismatch")
    require(sha256_file(pki_bundle_path) == plan["pki_bundle_sha256"],
            "PKI bundle hash mismatch")
    source_manifest = verify_bundle(
        root, source_manifest_path, source_bundle_path,
        plan["source_bundle_sha256"], plan["source_manifest_sha256"],
    )
    require(source_manifest.get("task") == "GB100-M15-01", "source bundle task mismatch")
    manifest_bytes = pki_manifest_path.read_bytes()
    manifest = load_json(pki_manifest_path, "PKI input manifest")
    validate_pki_manifest(manifest)
    require(manifest["source_manifest_sha256"] == plan["source_manifest_sha256"] and
            manifest["source_bundle_sha256"] == plan["source_bundle_sha256"],
            "PKI manifest is not bound to this source bundle")
    expected_names = {PKI_MANIFEST_NAME}
    expected_inputs: dict[str, dict[str, Any]] = {}
    for item in manifest["inputs"]:
        relative = require_relative_path(item["path"], "PKI manifest input").as_posix()
        expected_names.add("pki/" + relative)
        expected_inputs["pki/" + relative] = item
    try:
        with tarfile.open(pki_bundle_path, "r") as archive:
            members = archive.getmembers()
            require({member.name for member in members} == expected_names,
                    "PKI bundle contains undeclared or missing input")
            for member in members:
                require(member.isfile() and not member.issym() and not member.islnk(),
                        f"PKI bundle contains forbidden object: {member.name}")
                content = archive.extractfile(member)
                require(content is not None, f"PKI bundle cannot read: {member.name}")
                data = content.read()
                if member.name == PKI_MANIFEST_NAME:
                    require(data == manifest_bytes, "PKI manifest in bundle differs from supplied manifest")
                    continue
                item = expected_inputs[member.name]
                require(len(data) == item["size"] and hashlib.sha256(data).hexdigest() == item["sha256"],
                        f"PKI bundle input hash mismatch: {item['path']}")
    except (OSError, tarfile.TarError) as exc:
        raise TransportError(f"cannot verify PKI bundle: {exc}") from exc
    return manifest


def extract_verified_pki_bundle(root: Path, manifest: dict[str, Any], bundle: Path,
                                destination: Path) -> None:
    """Safely materialize a verified archive and run M3 again on its exact bytes."""
    destination.mkdir(parents=True, exist_ok=False)
    expected = {"pki/" + item["path"]: item for item in manifest["inputs"]}
    try:
        with tarfile.open(bundle, "r") as archive:
            for member in archive.getmembers():
                if member.name == PKI_MANIFEST_NAME:
                    continue
                item = expected.get(member.name)
                require(item is not None and member.isfile() and not member.issym() and not member.islnk(),
                        f"unsafe PKI member during extraction: {member.name}")
                relative = require_relative_path(item["path"], "PKI extracted input")
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                require(source is not None, f"cannot extract PKI input: {relative}")
                with target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                os.chmod(target, 0o644)
        verify_m3_build_inputs(root, destination)
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def verify_pki_prepared(root: Path, destination: Path, source_manifest_path: Path,
                        source_bundle_path: Path) -> dict[str, Any]:
    destination = validate_destination(destination)
    plan = load_json(destination / PKI_PLAN_NAME, "PKI transport plan")
    manifest = verify_pki_bundle(
        root, destination / PKI_MANIFEST_NAME, destination / PKI_BUNDLE_NAME,
        source_manifest_path, source_bundle_path, plan,
    )
    verify_pki_transport_archive(destination)
    verification = destination / f".m15-01-pki-verify-{uuid.uuid4().hex}"
    try:
        extract_verified_pki_bundle(root, manifest, destination / PKI_BUNDLE_NAME,
                                    verification / "current")
    finally:
        shutil.rmtree(verification, ignore_errors=True)
    return manifest


def prepare_pki(root: Path, destination: Path, source_manifest_path: Path,
                source_bundle_path: Path) -> Path:
    root = root.resolve()
    destination = validate_destination(destination)
    require(destination.is_dir(), "prepare-pki requires an existing prepared M15 source transport directory")
    final_paths = [destination / name for name in (
        PKI_MANIFEST_NAME, PKI_BUNDLE_NAME, PKI_PLAN_NAME, PKI_TRANSPORT_ARCHIVE_NAME,
    )]
    require(not any(path.exists() or path.is_symlink() for path in final_paths),
            "refusing to replace an existing PKI transport result")
    source_manifest_path = source_manifest_path.resolve()
    source_bundle_path = source_bundle_path.resolve()
    verify_bundle(root, source_manifest_path, source_bundle_path)
    source_manifest_sha = sha256_file(source_manifest_path)
    source_bundle_sha = sha256_file(source_bundle_path)
    manifest = pki_manifest_for(root, source_manifest_sha, source_bundle_sha)
    manifest_bytes = canonical_json(manifest)
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    staging = destination / f".m15-01-pki-staging-{uuid.uuid4().hex}"
    try:
        staging.mkdir()
        print("[M15-01 PKI 1/3] Revalidating promoted Russian PKI inputs with M3-04", flush=True)
        (staging / PKI_MANIFEST_NAME).write_bytes(manifest_bytes)
        write_pki_bundle(staging / PKI_BUNDLE_NAME, manifest_bytes, root, manifest)
        bundle_sha = sha256_file(staging / PKI_BUNDLE_NAME)
        (staging / PKI_PLAN_NAME).write_bytes(canonical_json(
            pki_plan_for(source_manifest_sha, source_bundle_sha, manifest_sha, bundle_sha)
        ))
        print("[M15-01 PKI 2/3] Checking hash binding, archive membership, and M3-04 again", flush=True)
        write_pki_transport_archive(staging)
        verify_pki_prepared(root, staging, source_manifest_path, source_bundle_path)
        print("[M15-01 PKI 3/3] Publishing the separately verified PKI transport", flush=True)
        for path in final_paths:
            os.replace(staging / path.name, path)
        staging.rmdir()
        return destination
    except BaseException:
        if staging.exists():
            print(f"M15-01 PKI: incomplete staging retained for inspection: {staging}", flush=True)
        raise


def stage_pki(root: Path, destination: Path, source_manifest_path: Path,
              source_bundle_path: Path, install_dir: Path) -> Path:
    """Install a separately verified input generation once, without replacement."""
    root = root.resolve()
    expected = (root / PKI_INPUT_DIR).resolve()
    require(install_dir.resolve() == expected,
            "PKI transport may only install at the canonical build-input location")
    require(not install_dir.exists() and not install_dir.is_symlink(),
            "refusing to replace existing Russian PKI build inputs")
    manifest = verify_pki_prepared(root, destination, source_manifest_path, source_bundle_path)
    staging = install_dir.parent / f".m15-01-pki-install-{uuid.uuid4().hex}"
    print("[M15-01 PKI] Extracting exact inputs and running M3-04 before build environment setup", flush=True)
    extract_verified_pki_bundle(root, manifest, destination / PKI_BUNDLE_NAME, staging)
    install_dir.parent.mkdir(parents=True, exist_ok=True)
    os.replace(staging, install_dir)
    return install_dir


def verify_prepared(destination: Path) -> dict[str, Any]:
    destination = validate_destination(destination)
    plan_path = destination / "transport-plan.json"
    manifest_path = destination / "source-manifest.json"
    bundle_path = destination / "source-bundle.tar"
    plan = load_json(plan_path, "transport plan")
    require(plan.get("task") == "GB100-M15-01", "transport plan другого задания")
    require(sha256_file(manifest_path) == plan.get("source_manifest_sha256"), "хеш source manifest не совпадает")
    manifest = verify_bundle(destination, manifest_path, bundle_path, plan.get("source_bundle_sha256"),
                             plan.get("source_manifest_sha256"))
    require(plan.get("private_build_inputs") == manifest.get("private_build_inputs"),
            "private input binding differs between source manifest and transport plan")
    for platform, details in plan.get("platforms", {}).items():
        require(details.get("source_manifest_sha256") == plan["source_manifest_sha256"]
                and details.get("source_bundle_sha256") == plan["source_bundle_sha256"],
                f"{platform}: команда не привязана к единому manifest и bundle")
    return manifest


def prepare(root: Path, contract_path: Path, destination: Path) -> Path:
    root = root.resolve()
    destination = validate_destination(destination)
    require(not destination.exists(), f"отказ от замены существующего результата: {destination}")
    contract_path = contract_path.resolve()
    try:
        contract_path.relative_to(root)
    except ValueError as exc:
        raise TransportError("контракт должен находиться в проекте") from exc
    contract = load_contract(contract_path)
    manifest = manifest_for(root, contract_path, contract)
    manifest_bytes = canonical_json(manifest)
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging_root = destination.parent / ".m15-01-staging"
    staging_root.mkdir(exist_ok=True)
    staging = staging_root / uuid.uuid4().hex
    try:
        staging.mkdir()
        print("[M15-01 1/3] Проверяю объявленные локальные входы и отсутствие секретов", flush=True)
        (staging / "source-manifest.json").write_bytes(manifest_bytes)
        write_bundle(staging / "source-bundle.tar", manifest_bytes, root, manifest)
        bundle_sha = sha256_file(staging / "source-bundle.tar")
        (staging / "transport-plan.json").write_bytes(canonical_json(
            plan_for(contract, manifest_sha, bundle_sha, manifest["private_build_inputs"])))
        print("[M15-01 2/3] Проверяю manifest и immutable source bundle", flush=True)
        verify_prepared(staging)
        print("[M15-01 3/3] Атомарно продвигаю проверенный локальный transport plan", flush=True)
        os.replace(staging, destination)
        return destination
    except BaseException:
        if staging.exists():
            print(f"M15-01: неполный результат сохранён в новом выделенном staging: {staging}", flush=True)
        raise


def result_files(remote_result: Path, result: dict[str, Any]) -> list[tuple[Path, str]]:
    files: list[tuple[Path, str]] = []
    for category in ("artifacts", "logs"):
        values = result.get(category)
        require(isinstance(values, list) and values, f"result: отсутствует объявленный {category}")
        for item in values:
            require(isinstance(item, dict) and isinstance(item.get("path"), str)
                    and SHA256_RE.fullmatch(item.get("sha256", "")), f"result: неверный {category}")
            relative = item["path"]
            require(relative.startswith(category + "/") and not Path(relative).is_absolute()
                    and ".." not in Path(relative).parts, f"result: необъявленный путь {relative}")
            path = (remote_result / relative).resolve()
            try:
                path.relative_to(remote_result.resolve())
            except ValueError as exc:
                raise TransportError(f"result: путь выходит из результата: {relative}") from exc
            require(path.is_file() and sha256_file(path) == item["sha256"],
                    f"result: хеш не совпадает: {relative}")
            # artifacts/ and logs/ are the only allowed return roots.  Check the
            # untrusted path below that declared root; source inputs still reject
            # their own artifacts/ directory altogether.
            # Native browser artifacts contain their restricted Safe Browsing
            # API key by design. Source inputs, metadata and logs may not.
            require_not_secret(path, relative.split("/", 1)[1],
                               allow_browser_api_key=category == "artifacts")
            files.append((path, relative))
    return files


def collect_return(destination: Path, platform: str, remote_result: Path) -> Path:
    destination = validate_destination(destination)
    manifest = verify_prepared(destination)
    plan = load_json(destination / "transport-plan.json", "transport plan")
    require(platform in plan["platforms"], "неизвестная платформа возвращаемого результата")
    remote_result = remote_result.resolve()
    result_path = remote_result / "result.json"
    result = load_json(result_path, "remote result")
    require_not_secret(result_path, "result.json")
    require(result.get("task") == "GB100-M15-01" and result.get("platform") == platform,
            "result не соответствует заданию или платформе")
    require(result.get("status") == "succeeded", "прерванная или неуспешная удалённая сборка не продвигается")
    require(result.get("source_manifest_sha256") == plan["source_manifest_sha256"]
            and result.get("source_bundle_sha256") == plan["source_bundle_sha256"],
            "result не привязан к локальному manifest/source bundle")
    files = result_files(remote_result, result)
    expected = {"result.json", *(relative for _, relative in files)}
    actual = {path.relative_to(remote_result).as_posix() for path in remote_result.rglob("*") if path.is_file()}
    require(actual == expected, "remote result содержит необъявленный файл")
    return_root = destination / "returned"
    quarantine = destination / "return-quarantine"
    quarantine.mkdir(exist_ok=True)
    final = return_root / f"{platform}-{plan['source_manifest_sha256'][:16]}"
    require(not final.exists(), "отказ от замены уже проверенного возвращаемого результата")
    staging = quarantine / uuid.uuid4().hex
    try:
        staging.mkdir()
        shutil.copy2(result_path, staging / "result.json")
        for source, relative in files:
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        copied_result = load_json(staging / "result.json", "скопированный remote result")
        result_files(staging, copied_result)
        require({path.relative_to(staging).as_posix() for path in staging.rglob("*") if path.is_file()} == expected,
                "копирование вернуло неполный или лишний файл")
        return_root.mkdir(exist_ok=True)
        os.replace(staging, final)
        return final
    except BaseException:
        if staging.exists():
            print(f"M15-01: возвращаемый результат оставлен в карантине: {staging}", flush=True)
        raise


def dry_run(root: Path, contract_path: Path, destination: Path) -> Path:
    prepared = prepare(root, contract_path, destination)
    plan = load_json(prepared / "transport-plan.json", "transport plan")
    rendered = canonical_json(plan)
    require(SECRET_CONTENT.search(rendered) is None, "dry-run plan содержит секрет")
    print("M15-01 dry-run: удалённые подключения и учётные данные не требуются", flush=True)
    for platform, details in plan["platforms"].items():
        for command in details["remote_commands"]:
            print(f"  {platform} {command['operation']}: {' '.join(command['argv'])}", flush=True)
    return prepared


def main() -> int:
    parser = argparse.ArgumentParser(description="Локальный transport contract GB100-M15-01")
    parser.add_argument(
        "action",
        choices=(
            "prepare", "verify", "verify-bundle", "dry-run", "collect",
            "prepare-pki", "verify-pki", "stage-pki",
        ),
    )
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--destination", type=Path, required=True,
                        help="новый выделенный локальный каталог; artifacts/quarantine запрещены")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--expected-bundle-sha256")
    parser.add_argument("--platform", choices=("ubuntu-amd64", "windows-x64"))
    parser.add_argument("--remote-result", type=Path)
    parser.add_argument("--source-manifest", type=Path)
    parser.add_argument("--source-bundle", type=Path)
    parser.add_argument("--install-pki-dir", type=Path)
    args = parser.parse_args()
    try:
        if args.action in {"prepare", "dry-run"}:
            operation = dry_run if args.action == "dry-run" else prepare
            result = operation(args.root, args.contract, args.destination)
            print(f"M15-01: подготовлено локально: {result}", flush=True)
        elif args.action == "verify":
            verify_prepared(args.destination)
            print("M15-01: локальный manifest и source bundle подтверждены", flush=True)
        elif args.action == "verify-bundle":
            require(args.manifest is not None and args.bundle is not None,
                    "verify-bundle требует --manifest и --bundle")
            verify_bundle(args.root, args.manifest, args.bundle, args.expected_bundle_sha256,
                          args.expected_manifest_sha256)
            print("M15-01: source bundle подтверждён", flush=True)
        elif args.action in {"prepare-pki", "verify-pki", "stage-pki"}:
            source_manifest = args.source_manifest or args.destination / "source-manifest.json"
            source_bundle = args.source_bundle or args.destination / "source-bundle.tar"
            if args.action == "prepare-pki":
                result = prepare_pki(args.root, args.destination, source_manifest, source_bundle)
                print(f"M15-01: verified PKI transport prepared locally: {result}", flush=True)
            elif args.action == "verify-pki":
                verify_pki_prepared(args.root, args.destination, source_manifest, source_bundle)
                print("M15-01: verified PKI transport and M3-04 gate confirmed", flush=True)
            else:
                require(args.install_pki_dir is not None,
                        "stage-pki requires --install-pki-dir")
                result = stage_pki(args.root, args.destination, source_manifest, source_bundle,
                                   args.install_pki_dir)
                print(f"M15-01: verified PKI inputs staged: {result}", flush=True)
        else:
            require(args.platform is not None and args.remote_result is not None,
                    "collect требует --platform и --remote-result")
            result = collect_return(args.destination, args.platform, args.remote_result)
            print(f"M15-01: возвращаемый результат атомарно продвинут: {result}", flush=True)
    except TransportError as exc:
        print(f"ОШИБКА M15-01: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
