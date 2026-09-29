#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Fetch, verify, install, and exercise Good Bear's pinned build tools."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import time
from urllib.request import Request, urlopen
import uuid

from project_temp import temporary_directory


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "config" / "toolchain-lock.json"
DEFAULT_ROOT = ROOT / "artifacts" / "toolchains"
DEFAULT_TARGET_IMAGE = "goodbear-ubuntu-m1-06:local"
EXPECTED_IDS = ("rust-and-cargo", "clang-llvm-lld", "wasi-sdk", "node-and-npm", "cbindgen")
HEX = set("0123456789abcdef")


class ToolchainError(RuntimeError):
    pass


def progress(message: str) -> None:
    print(message, flush=True)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ToolchainError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_lock(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolchainError(f"cannot load toolchain lock {path}: {exc}") from exc
    require(isinstance(value, dict), "toolchain lock must be a JSON object")
    return value


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= HEX


def validate_lock(lock: dict) -> None:
    require(lock.get("schema_version") == 1, "unsupported toolchain lock schema")
    require(lock.get("target") == "x86_64-unknown-linux-gnu", "unexpected toolchain target")
    require(lock.get("release_locale") == "ru", "toolchain lock must be Russian-only")
    components = lock.get("components")
    require(isinstance(components, list), "components must be a list")
    ids = tuple(item.get("id") for item in components if isinstance(item, dict))
    require(ids == EXPECTED_IDS, "toolchain lock must contain the exact ordered M1-06 components")
    for component in components:
        require(isinstance(component.get("version"), str) and component["version"],
                f"{component['id']}: missing version")
        for field in ("archive", "provenance", "install", "expected_commands"):
            if field in {"install", "expected_commands"} and component.get("exception") is not None:
                continue
            require(isinstance(component.get(field), dict), f"{component['id']}: missing {field}")
        archive = component["archive"]
        provenance = component["provenance"]
        for block, label in ((archive, "archive"), (provenance, "provenance")):
            url = block.get("url")
            require(isinstance(url, str) and url.startswith("https://"),
                    f"{component['id']}: {label} URL must be HTTPS")
            require(is_sha256(block.get("sha256")),
                    f"{component['id']}: {label} sha256 is malformed")
        require(isinstance(archive.get("filename"), str) and archive["filename"] and
                "/" not in archive["filename"], f"{component['id']}: invalid archive filename")
        signature = component.get("detached_signature")
        if signature is not None:
            require(isinstance(signature, dict) and isinstance(signature.get("url"), str) and
                    signature["url"].startswith("https://") and is_sha256(signature.get("sha256")),
                    f"{component['id']}: malformed detached signature")
        require(component.get("exception") is None,
                f"{component['id']}: M1-06 admits no uninstalled toolchain exceptions")
    by_id = {item["id"]: item for item in components}
    require(by_id["rust-and-cargo"]["version"] == "1.98.0", "Rust/Cargo pin must be 1.98.0")
    require(by_id["clang-llvm-lld"]["version"] == "22.1.8", "LLVM pin must be 22.1.8")
    wasi = by_id["wasi-sdk"]
    require(wasi["version"] == "33.0", "WASI SDK pin must be 33.0")
    require(wasi["install"].get("prefix") == "wasi-sdk", "WASI SDK prefix is unsafe")
    require(wasi["provenance"].get("kind") == "official-wasi-sdk-release-api",
            "WASI sysroot must use official release provenance")
    require(wasi["provenance"].get("release_tag") == "wasi-sdk-33", "WASI SDK release tag drift")
    require(by_id["node-and-npm"]["version"] == "24.19.0", "Node pin must be 24.19.0")
    require(by_id["node-and-npm"].get("npm_version") == "11.17.0", "npm pin must be 11.17.0")
    require(by_id["cbindgen"]["version"] == "0.29.4", "cbindgen pin must be 0.29.4")


def fetch(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "Good-Bear-toolchain-installer/1"})
    with urlopen(request, timeout=60) as response:
        return response.read()


def download_file(url: str, destination: Path, label: str) -> None:
    request = Request(url, headers={"User-Agent": "Good-Bear-toolchain-installer/1"})
    try:
        with urlopen(request, timeout=60) as response, destination.open("wb") as output:
            total = int(response.headers.get("Content-Length", "0"))
            copied = 0
            last_report = time.monotonic()
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                output.write(block)
                copied += len(block)
                now = time.monotonic()
                if copied % (32 * 1024 * 1024) < len(block) or now - last_report >= 15:
                    suffix = f"/{total}" if total else ""
                    progress(f"Downloaded {copied}{suffix} bytes for {label}")
                    last_report = now
    except OSError as exc:
        raise ToolchainError(f"cannot download {label}: {exc}") from exc


def fetch_verified_metadata(component: dict, offline: bool) -> None:
    if offline:
        progress(f"Offline provenance check deferred for {component['id']}")
        return
    progress(f"Verifying official provenance for {component['id']}")
    try:
        data = fetch(component["provenance"]["url"])
    except OSError as exc:
        raise ToolchainError(f"cannot fetch provenance for {component['id']}: {exc}") from exc
    provenance = component["provenance"]
    if provenance["kind"] in {"official-llvm-release-api", "official-wasi-sdk-release-api"}:
        try:
            release = json.loads(data)
            asset = next(item for item in release["assets"]
                         if item["name"] == component["archive"]["filename"])
        except (KeyError, StopIteration, json.JSONDecodeError) as exc:
            raise ToolchainError("LLVM release API does not describe the pinned archive") from exc
        expected_tag = (f"llvmorg-{component['version']}" if provenance["kind"] == "official-llvm-release-api"
                        else provenance["release_tag"])
        require(release.get("tag_name") == expected_tag,
                f"{component['id']} release API returned an unexpected tag")
        require(asset.get("digest") == f"sha256:{component['archive']['sha256']}",
                f"{component['id']} release API archive digest drift")
    elif provenance["kind"] == "official-crates-io-api":
        try:
            release = json.loads(data)
            published = release["version"]
        except (KeyError, json.JSONDecodeError) as exc:
            raise ToolchainError("crates.io metadata does not describe the pinned crate") from exc
        require(published.get("num") == component["version"],
                "crates.io metadata returned an unexpected cbindgen version")
        require(published.get("checksum") == component["archive"]["sha256"],
                "crates.io metadata archive checksum drift")
    else:
        require(sha256_bytes(data) == provenance["sha256"],
                f"official provenance drift for {component['id']}")
    signature = component.get("detached_signature")
    if signature:
        try:
            signature_data = fetch(signature["url"])
        except OSError as exc:
            raise ToolchainError(f"cannot fetch detached signature for {component['id']}: {exc}") from exc
        require(sha256_bytes(signature_data) == signature["sha256"],
                f"detached signature drift for {component['id']}")


def safe_extract(archive: Path, destination: Path) -> Path:
    try:
        with tarfile.open(archive, "r:*") as tar:
            members = tar.getmembers()
            require(members, f"archive is empty: {archive.name}")
            member_paths = [PurePosixPath(member.name) for member in members if member.name]
            roots = {path.parts[0] for path in member_paths if path.parts}
            require(len(roots) == 1, f"archive has ambiguous root: {archive.name}")
            progress(f"Validating {len(members)} archive paths for {archive.name}")
            for member in members:
                require(not member.isdev() and not member.isfifo(),
                        f"archive has unsupported special entry: {archive.name}")
                path = PurePosixPath(member.name)
                require(not path.is_absolute() and ".." not in path.parts,
                        f"archive path escapes destination: {archive.name}")
            # Keep a lexical traversal check above, then use tarfile's data
            # filter for link-target checks.  Resolving every prospective path
            # against an expanding destination tree is quadratic for the
            # pinned LLVM/WASI archives and made host-native runs appear stuck.
            extracted = 0

            def data_filter(member: tarfile.TarInfo, destination_path: str) -> tarfile.TarInfo | None:
                nonlocal extracted
                extracted += 1
                if extracted == 1 or extracted == len(members) or extracted % 1000 == 0:
                    progress(f"Extracting {archive.name}: {extracted}/{len(members)} entries")
                return tarfile.data_filter(member, destination_path)

            tar.extractall(destination, filter=data_filter)
    except (OSError, tarfile.TarError) as exc:
        raise ToolchainError(f"cannot extract {archive.name}: {exc}") from exc
    root = destination / next(iter(roots))
    require(root.is_dir(), f"archive root is absent: {archive.name}")
    return root


def run(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    progress("Running " + " ".join(command))
    try:
        result = subprocess.run(command, cwd=cwd, env=env, text=True, check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except FileNotFoundError as exc:
        raise ToolchainError(f"required command unavailable: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise ToolchainError(f"command failed ({' '.join(command)}): {exc.stdout.strip()}") from exc
    return result.stdout.strip()


def component(lock: dict, component_id: str) -> dict:
    return next(item for item in lock["components"] if item["id"] == component_id)


def fetch_archive(component_value: dict, cache: Path, offline: bool) -> Path:
    archive = component_value["archive"]
    cached = cache / archive["filename"]
    if cached.exists():
        if sha256_file(cached) == archive["sha256"]:
            progress(f"Using verified cached archive {cached.name}")
            return cached
        raise ToolchainError(f"cached archive hash mismatch: {cached}")
    require(not offline, f"offline mode needs cached archive: {cached.name}")
    progress(f"Downloading {component_value['id']} archive")
    partial = cache / f".{archive['filename']}.{uuid.uuid4().hex}.partial"
    download_file(archive["url"], partial, component_value["id"])
    require(sha256_file(partial) == archive["sha256"],
            f"downloaded archive hash mismatch for {component_value['id']}")
    os.replace(partial, cached)
    progress(f"Promoted verified archive {cached.name} to local cache")
    return cached


def install_rust(archive: Path, stage: Path) -> None:
    extracted = safe_extract(archive, stage / "extract-rust")
    installer = extracted / "install.sh"
    require(installer.is_file(), "Rust archive lacks install.sh")
    run([str(installer), f"--prefix={stage / 'rust'}", "--disable-ldconfig",
         "--components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu"])


def install_tar_prefix(archive: Path, stage: Path, prefix: str) -> None:
    extracted = safe_extract(archive, stage / f"extract-{prefix}")
    shutil.move(str(extracted), stage / prefix)


def toolchain_environment(prefix: Path) -> dict[str, str]:
    """Make interpreter-dispatched tools resolve siblings from this prefix first."""
    env = os.environ.copy()
    bins = (prefix / "rust" / "bin", prefix / "node" / "bin")
    env["PATH"] = os.pathsep.join(str(path) for path in bins) + os.pathsep + env.get("PATH", "")
    return env


def staged_rust_environment(stage: Path) -> dict[str, str]:
    """Build an environment whose Rust tools resolve only from this staging prefix first."""
    rust_bin = stage / "rust" / "bin"
    cargo = rust_bin / "cargo"
    rustc = rust_bin / "rustc"
    require(cargo.is_file(), "staged Rust installation is missing cargo")
    require(rustc.is_file(), "staged Rust installation is missing rustc")
    env = toolchain_environment(stage)
    env["CARGO_HOME"] = str(stage / "cargo-home")
    env["RUSTUP_HOME"] = str(stage / "rustup-home")
    return env


def install_cbindgen(archive: Path, stage: Path) -> None:
    extracted = safe_extract(archive, stage / "extract-cbindgen")
    cargo = stage / "rust" / "bin" / "cargo"
    env = staged_rust_environment(stage)
    run([str(cargo), "build", "--release", "--locked"], cwd=extracted, env=env)
    binary = extracted / "target" / "release" / "cbindgen"
    require(binary.is_file(), "locked cbindgen build did not produce its binary")
    destination = stage / "cbindgen" / "bin"
    destination.mkdir(parents=True)
    shutil.copy2(binary, destination / "cbindgen")


def check_prefix_versions(lock: dict, prefix: Path, *, include_llvm: bool = True) -> None:
    env = toolchain_environment(prefix)
    for component_value in lock["components"]:
        if component_value["id"] in {"clang-llvm-lld", "wasi-sdk"} and not include_llvm:
            continue
        install_prefix = prefix / component_value["install"]["prefix"]
        for command_name, expected in component_value["expected_commands"].items():
            executable = install_prefix / "bin" / command_name
            output = run([str(executable), "--version"], env=env)
            require(expected in output, f"{component_value['id']} returned unexpected {command_name} version: {output}")
        for required in component_value.get("required_paths", []):
            require((install_prefix / required).exists(),
                    f"{component_value['id']} is missing required path {required}")


def wasi_sysroot(prefix: Path) -> Path:
    """Return the locked WASI SDK sysroot below an installed toolchain prefix."""
    return prefix / "wasi-sdk" / "share" / "wasi-sysroot"


def focused_compatibility(prefix: Path, *, include_llvm: bool = True) -> None:
    progress("Running focused Rust, Node/npm, and cbindgen compatibility checks")
    rustc = prefix / "rust" / "bin" / "rustc"
    node = prefix / "node" / "bin" / "node"
    npm = prefix / "node" / "bin" / "npm"
    cbindgen = prefix / "cbindgen" / "bin" / "cbindgen"
    env = toolchain_environment(prefix)
    with temporary_directory(prefix="good-bear-toolchain-check-") as temporary:
        workspace = Path(temporary)
        rust_source = workspace / "check.rs"
        rust_source.write_text("fn main() { assert_eq!(2 + 2, 4); }\n", encoding="utf-8")
        run([str(rustc), str(rust_source), "-o", str(workspace / "check-rust")], env=env)
        run([str(workspace / "check-rust")])
        if include_llvm:
            clang = prefix / "llvm" / "bin" / "clang"
            clangxx = prefix / "llvm" / "bin" / "clang++"
            c_source = workspace / "check.c"
            c_source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            run([str(clang), "-fuse-ld=lld", str(c_source), "-o", str(workspace / "check-c")], env=env)
            run([str(workspace / "check-c")])
            cpp_source = workspace / "check.cpp"
            cpp_source.write_text("int main() { return 0; }\n", encoding="utf-8")
            run([str(clangxx), "-fuse-ld=lld", str(cpp_source), "-o", str(workspace / "check-cpp")], env=env)
            run([str(workspace / "check-cpp")])
            pinned_wasi_sysroot = wasi_sysroot(prefix)
            wasi_clang = prefix / "wasi-sdk" / "bin" / "clang"
            wasi_clangxx = prefix / "wasi-sdk" / "bin" / "clang++"
            wasi_c_source = workspace / "check-wasi.c"
            wasi_c_source.write_text(
                "#define _WASI_EMULATED_PROCESS_CLOCKS\n"
                "#include <time.h>\n"
                "int main(void) { return clock() == (clock_t)-1; }\n",
                encoding="utf-8",
            )
            run([str(wasi_clang), "--target=wasm32-wasi", f"--sysroot={pinned_wasi_sysroot}",
                 "-D_WASI_EMULATED_PROCESS_CLOCKS", str(wasi_c_source),
                 "-lwasi-emulated-process-clocks", "-o", str(workspace / "check-wasi-c.wasm")], env=env)
            wasi_cpp_source = workspace / "check-wasi.cpp"
            wasi_cpp_source.write_text("#include <cstring>\nint main() { return std::strlen(\"ru\") != 2; }\n", encoding="utf-8")
            run([str(wasi_clangxx), "--target=wasm32-wasi", f"--sysroot={pinned_wasi_sysroot}", str(wasi_cpp_source),
                 "-o", str(workspace / "check-wasi-cpp.wasm")], env=env)
        run([str(node), "--input-type=module", "--eval", "import('node:fs').then(() => process.exit(0))"], env=env)
        run([str(npm), "--offline", "--version"], env=env)
        header = workspace / "fixture.h"
        header.write_text("typedef struct { int member; } fixture;\n", encoding="utf-8")
        run([str(cbindgen), "--lang", "c", "--output", str(workspace / "ignored.h"), "--help"], env=env)


def marker(lock_path: Path, lock: dict) -> dict:
    return {
        "lock_sha256": sha256_file(lock_path),
        "target": lock["target"],
        "components": [{"id": item["id"], "version": item["version"],
                        "archive_sha256": item["archive"]["sha256"]}
                       for item in lock["components"]],
    }


def target_compatibility(prefix: Path, image: str) -> None:
    verifier = ROOT / "tools" / "verify_target_toolchain.py"
    require(verifier.is_file(), "target toolchain verifier is missing")
    progress("Running mandatory LLVM/WASI compatibility gate in pinned Ubuntu target")
    run(["docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges",
         "--mount", f"type=bind,src={prefix.resolve()},dst=/workspace/toolchains/current,ro",
         "--mount", f"type=bind,src={verifier.resolve()},dst=/workspace/verify_target_toolchain.py,ro",
         image, "python3.12", "/workspace/verify_target_toolchain.py",
         "--prefix", "/workspace/toolchains/current"])


def verify_installed_toolchain(prefix: Path, lock: dict, *, host_native: bool,
                               target_image: str) -> None:
    """Exercise a pinned prefix on its installation host or pinned target.

    A host-native build must not silently substitute a Docker runtime for its
    compiler checks.  It verifies the LLVM and WASI executables locally and
    records the ordinary lock-bound marker.  The default route retains the
    isolated Docker target gate, which remains required for distribution
    verification.
    """
    check_prefix_versions(lock, prefix, include_llvm=host_native)
    focused_compatibility(prefix, include_llvm=host_native)
    if host_native:
        progress("Host-native toolchain compatibility checks passed; Docker target gate is deferred")
        return
    target_compatibility(prefix, target_image)


def install(lock_path: Path, lock: dict, destination_root: Path, offline: bool, target_image: str,
            *, host_native: bool = False) -> Path:
    destination_root.mkdir(parents=True, exist_ok=True)
    cache = destination_root / "cache"
    cache.mkdir(exist_ok=True)
    final = destination_root / "current"
    expected_marker = marker(lock_path, lock)
    marker_path = final / ".good-bear-toolchain.json"
    if marker_path.is_file():
        require(json.loads(marker_path.read_text(encoding="utf-8")) == expected_marker,
                "existing toolchain does not match the current lock")
        verify_installed_toolchain(final, lock, host_native=host_native, target_image=target_image)
        progress("Existing verified toolchain passed focused compatibility checks")
        return final
    lock_file = destination_root / ".install.lock"
    with lock_file.open("a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        if marker_path.is_file():
            return install(lock_path, lock, destination_root, offline, target_image)
        staging = destination_root / f".staging-{uuid.uuid4().hex}"
        staging.mkdir()
        try:
            for component_value in lock["components"]:
                fetch_verified_metadata(component_value, offline)
                archive = fetch_archive(component_value, cache, offline)
                if component_value["id"] == "rust-and-cargo":
                    install_rust(archive, staging)
                elif component_value["id"] == "cbindgen":
                    install_cbindgen(archive, staging)
                else:
                    install_tar_prefix(archive, staging, component_value["install"]["prefix"])
            verify_installed_toolchain(staging, lock, host_native=host_native,
                                      target_image=target_image)
            (staging / ".good-bear-toolchain.json").write_text(
                json.dumps(expected_marker, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            os.replace(staging, final)
            progress(f"Promoted verified toolchain atomically to {final}")
            return final
        except BaseException:
            if staging.exists():
                quarantine = destination_root / "quarantine"
                quarantine.mkdir(exist_ok=True)
                os.replace(staging, quarantine / f"{staging.name}-{uuid.uuid4().hex}")
            raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--target-image", default=DEFAULT_TARGET_IMAGE)
    parser.add_argument(
        "--host-native",
        action="store_true",
        help=("verify the installed pinned toolchain on this host; defer the mandatory "
              "Docker target gate to a later distribution verification"),
    )
    args = parser.parse_args()
    try:
        lock_path = args.lock.resolve()
        lock = load_lock(lock_path)
        validate_lock(lock)
        if args.verify_only:
            for component_value in lock["components"]:
                fetch_verified_metadata(component_value, args.offline)
            progress("Good Bear M1-06 toolchain lock and official provenance verified")
        else:
            install(lock_path, lock, args.root.resolve(), args.offline, args.target_image,
                    host_native=args.host_native)
    except ToolchainError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
