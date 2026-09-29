#!/usr/bin/env python3
"""Verify the existing native Cloud Windows inputs without starting compilation.

This command creates source-free preflight evidence only. M13-01..05 source
freeze and an enforced offline build boundary are not yet supplied by the
runner workflow, so neither this tool nor its workflow accepts an execute flag.
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
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))
import materialize_firefox_source as materializer
import m15_remote_transport as transport
from windows_offline_worker import trusted_python_command

HEX256 = re.compile(r"[0-9a-f]{64}\Z")
REQUIRED_PYTHON_OWNERS = frozenset({
    "tools/run_m13_cloud_windows.py", "tools/windows_offline_worker.py",
    "tools/preflight_m15_cloud_windows.py", "tools/materialize_firefox_source.py",
    "tools/m15_remote_transport.py", "tools/host_build_context.py", "tools/project_temp.py",
    "tools/verify_m3_04_certificate_supply_chain.py", "tools/verify_m3_01_certificate_provenance.py",
    "tools/verify_m3_02_russian_pki_manifest.py",
    "tools/verify_firefox_baseline.py",
    "tools/safebrowsing_build_input.py",
})
EXECUTION_BLOCKERS = (
    "M13-01..05 passing evidence bound to this exact frozen source manifest is absent",
    "an enforced offline native-build boundary compatible with runner control is not verified",
)
SOURCE_DELTA_RECORD = ".good-bear-source-delta.json"
SOURCE_DELTA_PATHS = frozenset({
    "config/m15-12-safebrowsing-build-input.json",
    "tools/preflight_m15_cloud_windows.py",
    "tools/run_m13_cloud_windows.py",
    "tools/windows_offline_worker.py",
})


class PreflightError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreflightError(message)


def progress(message: str) -> None:
    print("[Windows native preflight] " + message, flush=True)


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    require(isinstance(value, dict), f"expected object in {path.name}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    size = path.stat().st_size
    completed = 0
    next_progress = 256 * 1024 * 1024
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            completed += len(block)
            if completed >= next_progress:
                progress(f"hashing {path.name}: {completed}/{size} bytes")
                next_progress += 256 * 1024 * 1024
    return digest.hexdigest()


def verify_python_import_tree(root: Path, entries: list[dict]) -> None:
    """Reject unreviewed code in the bounded import tree before native work."""
    declared = {entry["path"].casefold(): entry for entry in entries}
    require(len(declared) == len(entries), "case-ambiguous frozen input paths")
    require(REQUIRED_PYTHON_OWNERS.issubset(declared), "snapshot lacks trusted Python import owners")
    pending = [root / "tools"]
    while pending:
        directory = pending.pop()
        require(not directory.is_symlink() and not getattr(directory, "is_junction", lambda: False)(),
                "Python import directory is a reparse point")
        for path in directory.iterdir():
            require(not path.is_symlink() and not getattr(path, "is_junction", lambda: False)(),
                    "Python import entry is a reparse point")
            if path.is_dir():
                pending.append(path)
                continue
            extension = path.suffix.casefold()
            require(extension not in {".pyc", ".pyo"}, "source bytecode cannot supply trusted Python")
            if extension in {".py", ".pyd"}:
                entry = declared.get(path.relative_to(root).as_posix().casefold())
                require(entry is not None, "undeclared Python import file")
                require(path.stat().st_size == entry["size"] and sha256(path) == entry["sha256"],
                        "Python import bytes differ from frozen source")


def effective_frozen_entries(root: Path, entries: list[dict], expected_manifest: str,
                             expected_bundle: str) -> tuple[list[dict], dict | None]:
    """Permit one hash-bound source overlay over an otherwise immutable bundle.

    The base manifest remains authoritative for every non-overlaid file.  The
    record may replace only the native execution owners and must bind both
    their original manifest bytes and their new exact bytes.
    """
    record_path = root / SOURCE_DELTA_RECORD
    if not record_path.exists():
        return entries, None
    require(record_path.is_file() and not record_path.is_symlink(), "source delta record is unsafe")
    record = load(record_path)
    require(record.get("schema_version") == 1 and record.get("kind") == "goodbear-m15-03-source-overlay" and
            record.get("base_manifest_sha256") == expected_manifest and
            record.get("base_bundle_sha256") == expected_bundle,
            "source delta is not bound to this frozen source")
    replacements = record.get("replacements")
    require(isinstance(replacements, list) and {item.get("path") for item in replacements if isinstance(item, dict)} ==
            SOURCE_DELTA_PATHS and len(replacements) == len(SOURCE_DELTA_PATHS),
            "source delta replacement scope differs")
    declared = {item.get("path"): item for item in entries}
    require(len(declared) == len(entries), "frozen source manifest has duplicate paths")
    effective = {path: dict(item) for path, item in declared.items()}
    for replacement in replacements:
        require(isinstance(replacement, dict) and set(replacement) ==
                {"path", "base_sha256", "base_size", "sha256", "size"},
                "source delta replacement schema differs")
        path = replacement["path"]
        original = declared.get(path)
        require(original is not None and replacement["base_sha256"] == original.get("sha256") and
                replacement["base_size"] == original.get("size"),
                "source delta base bytes differ")
        require(isinstance(replacement["sha256"], str) and bool(HEX256.fullmatch(replacement["sha256"])) and
                isinstance(replacement["size"], int) and replacement["size"] > 0,
                "source delta replacement digest is malformed")
        effective[path].update(sha256=replacement["sha256"], size=replacement["size"])
    ordered = [effective[item["path"]] for item in entries]
    return ordered, {"record_sha256": sha256(record_path), "replacements": sorted(SOURCE_DELTA_PATHS)}


def verify_frozen_source(root: Path, source: Path, manifest_path: Path, bundle_path: Path,
                         expected_manifest: str, expected_bundle: str) -> dict:
    require(bool(HEX256.fullmatch(expected_manifest)) and bool(HEX256.fullmatch(expected_bundle)),
            "exact lowercase source manifest and bundle SHA-256 pins are required")
    progress("verifying the frozen manifest and bundle against caller-supplied pins")
    manifest = transport.verify_bundle(root, manifest_path, bundle_path, expected_bundle, expected_manifest)
    entries = manifest.get("declared_inputs", [])
    require(isinstance(entries, list) and all(isinstance(item, dict) for item in entries),
            "frozen source manifest entries are malformed")
    entries, source_delta = effective_frozen_entries(root, entries, expected_manifest, expected_bundle)
    required = {
        "config/firefox-baseline.json", "config/m15-03-windows-toolchain-lock.json",
        "build/windows/mozconfig.release-lto", "tools/preflight_m15_cloud_windows.py",
        "patches/series", *transport.REQUIRED_RUSSIAN_L10N,
        *REQUIRED_PYTHON_OWNERS,
    }
    require(required.issubset({item.get("path") for item in entries}),
            "frozen snapshot lacks the native preflight, toolchain, mozconfig, or Russian inputs")
    for index, item in enumerate(entries, start=1):
        path = transport.resolve_relative(root, item["path"], "frozen input")
        require(path.is_file() and not path.is_symlink(), f"frozen input missing: {item['path']}")
        require(path.stat().st_size == item["size"] and sha256(path) == item["sha256"],
                f"extracted input differs from frozen snapshot: {item['path']}")
        if index % 250 == 0 or index == len(entries):
            progress(f"verified extracted inputs: {index}/{len(entries)}")
    verify_python_import_tree(root, entries)
    baseline_path = root / "config/firefox-baseline.json"
    baseline = load(baseline_path)
    version, archive, source_pin = materializer.baseline_values(baseline, baseline_path)
    require(version == "156.0", "native Cloud preflight requires the approved Firefox 156.0 baseline")
    require(manifest.get("upstream") == {
        "product": baseline.get("product"), "version": version,
        "revision": baseline.get("vcs", {}).get("revision"),
        "archive": source_pin.get("archive_path"), "archive_sha256": source_pin.get("sha256"),
    }, "frozen manifest and current Firefox baseline differ")
    canonical = materializer.resolve_under(
        archive.parent, "worktrees/" + materializer.archive_root_name(version), "materialized source")
    require(source.resolve() == canonical, "source is not the canonical baseline worktree")
    marker_path = source / ".good-bear-materialization.json"
    marker = load(marker_path)
    require(all(marker.get(key) == expected for key, expected in {
        "version": version, "baseline_config_sha256": sha256(baseline_path),
        "source_sha256": source_pin["sha256"], "source_sha512": source_pin["sha512"],
    }.items()), "materialization marker does not bind the frozen baseline")
    patches = [{"path": item.relative_to(root / "patches").as_posix(), "sha256": sha256(item)}
               for item in materializer.read_series(root / "patches")]
    require(marker.get("patches") == patches, "materialized patch series differs from frozen inputs")
    require((source / "browser/config/version.txt").read_text(encoding="utf-8").strip() == version,
            "materialized browser version differs from frozen baseline")
    mozconfig = (root / "build/windows/mozconfig.release-lto").read_text(encoding="utf-8")
    require("export MOZ_LTO=full" in mozconfig and "ac_add_options --enable-release" in mozconfig and
            "mk_add_options MOZ_CO_LOCALES=ru" in mozconfig,
            "Windows release configuration no longer declares full LTO and Russian repack")
    result = {"firefox_version": version, "firefox_revision": baseline["vcs"]["revision"],
            "manifest_sha256": expected_manifest, "bundle_sha256": expected_bundle,
            "materialization_marker_sha256": sha256(marker_path), "declared_inputs": len(entries)}
    if source_delta is not None:
        result["source_delta"] = source_delta
    return result


def components(lock: dict) -> dict:
    require(lock.get("task") == "GB100-M15-03" and lock.get("platform") == "Windows Server 2022 x64",
            "toolchain lock is not the native Cloud Windows contract")
    require(lock.get("network_policy", {}).get("build_after_source_freeze") == "network forbidden",
            "native build network policy changed")
    values = lock.get("components", [])
    require(isinstance(values, list) and all(isinstance(item, dict) for item in values),
            "malformed Windows toolchain components")
    result = {item.get("id"): item for item in values}
    require(len(result) == len(values) and set(result) == {
        "visual-studio-build-tools", "mozilla-build", "git-for-windows", "python", "rust", "node", "nasm", "llvm",
        "firefox156-mozmake", "firefox156-nsis", "zstd",
    }, "native Windows toolchain component inventory differs")
    for item in values:
        require(isinstance(item.get("version"), str) and bool(re.fullmatch(r"[0-9A-Za-z._+-]+", item["version"])),
                "invalid pinned toolchain version")
        require(isinstance(item.get("sha256"), str) and bool(HEX256.fullmatch(item["sha256"])),
                "invalid pinned toolchain archive SHA-256")
        require(urlsplit(item.get("url", "")).scheme == "https", "toolchain archive must be pinned over HTTPS")
    return result


def cached_filename(component: dict) -> str:
    if component["id"] == "visual-studio-build-tools":
        return f"vs_BuildTools-{component['version']}.exe"
    name = unquote(urlsplit(component["url"]).path.rsplit("/", 1)[-1])
    require(name and Path(name).name == name and "/" not in name and "\\" not in name,
            "toolchain cache filename is unsafe")
    return name


def verify_cached_toolchain(lock: dict, cache: Path) -> dict:
    pinned = components(lock)
    verified = {}
    for name, component in pinned.items():
        path = cache / cached_filename(component)
        require(path.is_file() and not path.is_symlink(), f"pinned toolchain cache is absent: {path.name}")
        progress(f"checking pinned cache: {name}")
        require(sha256(path) == component["sha256"], f"pinned toolchain cache hash mismatch: {name}")
        verified[name] = {"version": component["version"], "archive_sha256": component["sha256"]}
    return verified


def probe(command: list[str], env: dict[str, str]) -> str:
    result = subprocess.run(command, text=True, capture_output=True, check=False, env=env)
    require(result.returncode == 0, f"installed tool probe failed: {Path(command[0]).name}")
    output = (result.stdout or result.stderr).strip()
    require(output, f"installed tool returned no version: {Path(command[0]).name}")
    return output


def version_matches(output: str, expected: str) -> bool:
    return output == expected or (output.startswith(expected) and
                                 (expected.endswith(" ") or output[len(expected):len(expected) + 1].isspace()))


def toolchain_fingerprint(evidence: dict) -> str:
    require(evidence.get("preflight_passed") is True and evidence.get("m3_04") == "passed",
            "toolchain binding requires successful native preflight")
    require(bool(HEX256.fullmatch(evidence.get("toolchain_lock_sha256", ""))) and
            isinstance(evidence.get("installed_tools"), dict) and evidence["installed_tools"] and
            isinstance(evidence.get("toolchain_cache"), dict) and evidence["toolchain_cache"],
            "toolchain identity is incomplete")
    value = {name: evidence[name] for name in
             ("toolchain_lock_sha256", "installed_tools", "toolchain_cache")}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def native_environment() -> dict[str, str]:
    # Keep only Windows process/path inputs; never forward runner credentials.
    allowed = {"systemroot", "windir", "comspec", "programfiles", "programfiles(x86)",
               "programdata", "userprofile", "appdata", "localappdata", "temp", "tmp", "pathext"}
    environment = {key: value for key, value in os.environ.items() if key.lower() in allowed}
    # MozillaBuild separates Windows-native build commands from its MSYS helpers.
    environment["PATH"] = r"C:\GoodBear\tools\firefox156-toolchains\mozmake;C:\GoodBear\tools\firefox156-toolchains\nsis;C:\mozilla-build\bin;C:\mozilla-build\msys2\usr\bin;C:\Windows\System32;C:\Windows"
    return environment


def verify_installed_tools(lock: dict, env: dict[str, str]) -> dict:
    pinned = components(lock)
    tools = Path(lock["install_root"])
    evidence = load(tools.parent / "toolchain-evidence.json")
    vs = pinned["visual-studio-build-tools"]
    expected_vs_installation = vs.get("installation_version", vs["version"])
    require(evidence.get("build_tools") == expected_vs_installation, "Cloud Visual Studio bootstrap evidence is stale")
    msvc = evidence.get("msvc", "")
    require(isinstance(msvc, str) and bool(re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", msvc)) and
            msvc.startswith(vs["required_msvc_directory_version"] + "."), "Cloud MSVC evidence is not the pinned family")
    require(Path(sys.executable).resolve() == (tools / "Python312/python.exe").resolve(),
            "preflight must use the pinned Cloud Python executable")
    rust = pinned["rust"]["version"].removesuffix("-x86_64-pc-windows-msvc")
    llvm = tools / f"clang+llvm-{pinned['llvm']['version']}-x86_64-pc-windows-msvc/bin"
    specifications = {
        "python": (tools / "Python312/python.exe", ["--version"], "Python " + pinned["python"]["version"]),
        "git": (Path(pinned["git-for-windows"]["executable"]), ["--version"], "git version " + pinned["git-for-windows"]["version"]),
        "rust": (tools / f"rust-{rust}/bin/rustc.exe", ["--version"], "rustc " + rust + " "),
        "cargo": (tools / f"rust-{rust}/bin/cargo.exe", ["--version"], "cargo " + rust + " "),
        "node": (tools / f"node-v{pinned['node']['version']}-win-x64/node.exe", ["--version"], "v" + pinned["node"]["version"]),
        "nasm": (tools / f"nasm-{pinned['nasm']['version']}/nasm.exe", ["-v"], "NASM version " + pinned["nasm"]["version"] + " "),
        "llvm": (llvm / "clang-cl.exe", ["--version"], "clang version " + pinned["llvm"]["version"]),
    }
    observed = {}
    for name, (executable, arguments, expected) in specifications.items():
        require(executable.is_file(), f"installed pinned executable is absent: {name}")
        output = probe([str(executable), *arguments], env)
        require(version_matches(output, expected), f"installed executable version differs: {name}")
        observed[name] = {"version": output.splitlines()[0], "executable_sha256": sha256(executable)}
    vswhere = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe")
    require(vswhere.is_file(), "reviewed Visual Studio discovery tool is absent")
    arguments = [str(vswhere), "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64"]
    require(probe([*arguments, "-property", "installationVersion"], env) == expected_vs_installation,
            "installed Visual Studio version differs from its pinned bootstrap")
    require(Path(probe([*arguments, "-property", "installationPath"], env)).resolve() ==
            (tools.parent / "vs-buildtools").resolve(), "Visual Studio path differs from the reviewed Cloud bootstrap")
    required_paths = [
        tools.parent / "vs-buildtools/Common7/Tools/VsDevCmd.bat",
        tools.parent / f"vs-buildtools/VC/Tools/MSVC/{msvc}/bin/Hostx64/x64/cl.exe",
        Path(r"C:\Program Files (x86)\Windows Kits\10\bin") / vs["required_windows_sdk"] / "x64/rc.exe",
        llvm / "lld-link.exe", Path(r"C:\mozilla-build\start-shell.bat"),
        Path(r"C:\mozilla-build\msys2\usr\bin\bash.exe"),
        Path(r"C:\mozilla-build\msys2\usr\bin\openssl.exe"),
        tools / "firefox156-toolchains/mozmake/mozmake.exe",
        tools / "firefox156-toolchains/nsis/makensis.exe",
        tools / "zstd-v1.5.7-win64/zstd.exe",
    ]
    for path in required_paths:
        require(path.is_file(), f"native build prerequisite is absent: {path}")
    required_paths.append(vswhere)
    return {"executables": observed,
            "native_prerequisite_sha256": {str(path): sha256(path) for path in required_paths},
            "msvc_directory": msvc, "windows_sdk": vs["required_windows_sdk"],
            "installed_executable_hashes_are_observations_not_new_trust_pins": True}


def run(args: argparse.Namespace) -> dict:
    require(sys.platform == "win32", "native preflight requires the real Windows runner")
    from host_build_context import SOURCE
    root = ROOT.resolve()
    frozen = verify_frozen_source(root, SOURCE, args.manifest, args.bundle,
                                  args.expected_manifest_sha256, args.expected_bundle_sha256)
    lock = load(root / "config/m15-03-windows-toolchain-lock.json")
    cache = Path(lock["install_root"]).parent / "toolchain-downloads"
    verified_cache = verify_cached_toolchain(lock, cache)
    environment = native_environment()
    installed = verify_installed_tools(lock, environment)
    progress("running the authoritative M3-04 gate on the staged Russian PKI inputs")
    result = subprocess.run(
        trusted_python_command(
            sys.executable, root / "tools/verify_m3_04_certificate_supply_chain.py",
            ["--build-input-dir", str(root / "artifacts/certificates/build-inputs/current")],
            root / "artifacts/build-tmp/python-startup"),
        env=environment, check=False)
    require(result.returncode == 0, "M3-04 rejected the staged Russian PKI inputs")
    return {"schema_version": 1, "task": "GB100-M13-06", "kind": "native-cloud-preflight-only",
            "preflight_passed": True, "build_executed": False, "execution_allowed": False,
            "execution_blockers": list(EXECUTION_BLOCKERS), "frozen_source": frozen,
            "toolchain_lock_sha256": sha256(root / "config/m15-03-windows-toolchain-lock.json"),
            "toolchain_cache": verified_cache, "installed_tools": installed,
            "m3_04": "passed", "locale": "ru source inputs verified; no binary claim",
            "product_artifacts": [], "public_release_allowed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-bundle-sha256", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = args.report.resolve()
    if report.exists() or report.is_relative_to(ROOT.resolve()):
        progress("refusing an existing report or a report inside the frozen source root")
        return 1
    try:
        evidence = run(args)
    except (PreflightError, transport.TransportError, materializer.MaterializationError,
            OSError, ValueError, KeyError, TypeError) as exc:
        evidence = {"schema_version": 1, "task": "GB100-M13-06", "kind": "native-cloud-preflight-only",
                    "preflight_passed": False, "build_executed": False, "execution_allowed": False,
                    "blocker": str(exc), "product_artifacts": [], "public_release_allowed": False}
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    progress("preflight passed; compilation remains blocked" if evidence["preflight_passed"] else
             "preflight failed: " + evidence["blocker"])
    return 0 if evidence["preflight_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
