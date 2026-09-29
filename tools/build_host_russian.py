#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Build a Russian-only Good Bear host candidate through Firefox's l10n flow."""

from __future__ import annotations

import argparse
import ast
import codecs
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from host_build_context import (
    ContextError,
    HostBuildContext,
    ROOT,
    SOURCE,
    reject_conflicting_toolchain_environment,
)
from wasm2c_host_cpp_preflight import PreflightError, probe as wasm2c_host_cpp_probe
from safebrowsing_build_input import BuildInputError


BASE_INPUT_DIR = "goodbear-base-input"
RUSSIAN_PKI_BUILD_INPUT_DIR = ROOT / "artifacts" / "certificates" / "build-inputs" / "current"


class BuildError(RuntimeError):
    pass


def verify_russian_pki_build_inputs(build_input_dir: Path) -> None:
    """Require the production M3 gate before exposing PKI files to mach.

    The separate M15 transport validates its archive before staging it, but the
    build host repeats the authoritative M3-04 certificate and chain checks on
    the exact directory that will be passed to the build environment.
    """
    verifier_path = ROOT / "tools" / "verify_m3_04_certificate_supply_chain.py"
    spec = importlib.util.spec_from_file_location("good_bear_build_host_m3_04", verifier_path)
    if spec is None or spec.loader is None:
        raise BuildError("cannot load the M3-04 Russian PKI supply-chain verifier")
    verifier = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(verifier)
        verifier.run(build_input_dir)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        raise BuildError(f"M3-04 Russian PKI build-input validation failed: {exc}") from exc


def command_plan(
    jobs: int, *, configure: bool = False
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if jobs < 1 or jobs > 4:
        raise BuildError("jobs must be between 1 and 4")
    plan = []
    if configure:
        plan.append(("configure base Firefox inputs", ("configure",)))
    plan.extend((
        ("build base Firefox inputs", ("build", f"-j{jobs}")),
        ("package internal base inputs", ("package",)),
        ("repack the only shipped locale: ru", ("build", "installers-ru")),
    ))
    return tuple(plan)


def requires_initial_configure(objdir: Path) -> bool:
    """Configure only an unconfigured object directory.

    `mach build` still owns detection of meaningful configuration-input
    changes. Avoiding an unconditional `mach configure` preserves make's
    incremental dependency timestamps for ordinary source and asset edits.
    """
    return not (objdir / "config.status").is_file()


def find_base_package(objdir: Path) -> Path:
    candidates = sorted(
        (objdir / BASE_INPUT_DIR).rglob("goodbear-*.en-US.linux-x86_64.tar.xz")
    )
    if len(candidates) != 1:
        raise BuildError(
            "expected exactly one packaged en-US base input, found: "
            + ", ".join(str(candidate) for candidate in candidates)
        )
    candidate = candidates[0]
    if candidate.resolve() != candidate.absolute() or not candidate.resolve().is_relative_to(objdir.resolve()):
        raise BuildError("base package must remain a regular file inside the canonical object directory")
    return candidate.resolve()


def stage_en_us_outputs(objdir: Path) -> list[Path]:
    dist = objdir / "dist"
    inputs = sorted(path for path in dist.rglob("goodbear-*.en-US.*") if path.is_file())
    destination = objdir / BASE_INPUT_DIR
    destination.mkdir(exist_ok=True)
    for input_path in inputs:
        staged_path = destination / input_path.relative_to(dist)
        staged_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(input_path), staged_path)
    return inputs


def stage_base_inputs(objdir: Path) -> Path:
    if not stage_en_us_outputs(objdir):
        raise BuildError("the base package step produced no en-US inputs to stage")
    return find_base_package(objdir)


def run(command: tuple[str, ...], environment: dict[str, str], *, context: HostBuildContext) -> None:
    context.validate_safebrowsing()
    if environment.get("MOZCONFIG") != str(context.mozconfig) or environment.get("MOZ_OBJDIR") != str(context.objdir):
        raise BuildError("mach environment differs from the verified canonical context")
    redactor = context.safebrowsing_log_redactor()
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    process = subprocess.Popen(
        [sys.executable, "mach", *command],
        cwd=SOURCE,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert process.stdout is not None
    try:
        with process.stdout:
            for chunk in iter(lambda: process.stdout.read1(8192), b""):
                print(decoder.decode(redactor.feed(chunk)), end="", flush=True)
            print(decoder.decode(redactor.finish(), final=True), end="", flush=True)
    except BaseException:
        process.kill()
        process.wait()
        raise
    if process.wait():
        raise BuildError(f"mach {' '.join(command)} failed")


def file_digest(path: Path, *, maximum: int | None = None) -> str:
    if path.is_symlink() or not path.is_file():
        raise BuildError("required build evidence is not a regular file")
    digest = hashlib.sha256()
    length = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            length += len(block)
            if maximum is not None and length > maximum:
                raise BuildError("build evidence exceeds its size bound")
            digest.update(block)
    return digest.hexdigest()


CONFIG_STATUS_TYPED_SUBSTS = {"CC_TYPE": "CompilerType", "HOST_CC_TYPE": "CompilerType",
    "WASM_CC_TYPE": "CompilerType", "CPU_ARCH": "RaiseErrorOnUse", "HOST_CPU_ARCH": "CPU",
    "TARGET_CPU": "CPU", "HOST_OS_ARCH": "Kernel", "TARGET_KERNEL": "Kernel",
    "TARGET_ENDIANNESS": "Endianness", "TARGET_OS": "OS"}


def configured_safebrowsing_subst(node: ast.AST) -> dict[str, object]:
    try:
        value = ast.literal_eval(node)
        if isinstance(value, dict):
            return value
    except (ValueError, TypeError):
        pass
    if not isinstance(node, ast.Dict):
        raise BuildError("unsupported config.status substs")
    result = {}
    for key, value in zip(node.keys, node.values):
        name = ast.literal_eval(key)
        if not isinstance(name, str) or name in result:
            raise BuildError("unsupported config.status substs key")
        if name == "MOZ_GOOGLE_SAFEBROWSING_API_KEY":
            result[name] = ast.literal_eval(value)
            continue
        try:
            ast.literal_eval(value)
            continue
        except (ValueError, TypeError):
            expected = CONFIG_STATUS_TYPED_SUBSTS.get(name)
            if not (expected and isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and
                    value.func.id == expected and not value.keywords and len(value.args) == 1 and
                    isinstance(value.args[0], ast.Constant) and isinstance(value.args[0].value, str)):
                raise BuildError("unsupported config.status substs value")
    return result


def verify_configured_key(context: HostBuildContext) -> str:
    """Read Firefox 156's literal config.status assignments; never execute it."""
    context.validate_safebrowsing()
    path = context.objdir / "config.status"
    config_hash = file_digest(path, maximum=8 * 1024 * 1024)
    try:
        data = path.read_bytes()
        if len(data) > 8 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != config_hash:
            raise BuildError("configured input changed while being read")
        tree = ast.parse(data)
        values = {}
        allowed = {"substs", "defines", "mozconfig", "topobjdir", "topsrcdir", "__all__"}
        generated_import = ast.dump(ast.parse("from mozbuild.configure.constants import *").body[0])
        generated_main = ast.dump(ast.parse(
            "if __name__ == '__main__':\n"
            "    from mozbuild.config_status import config_status\n"
            "    args = dict([(name, globals()[name]) for name in __all__])\n"
            "    config_status(**args)\n").body[0])
        import_count = main_count = 0
        for statement in tree.body:
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                target = statement.targets[0]
                if isinstance(target, ast.Name) and target.id in allowed:
                    if target.id in values:
                        raise BuildError("ambiguous config.status assignments")
                    values[target.id] = (configured_safebrowsing_subst(statement.value)
                                         if target.id == "substs" else ast.literal_eval(statement.value))
                    continue
            if ast.dump(statement) == generated_import:
                import_count += 1
            elif ast.dump(statement) == generated_main:
                main_count += 1
            else:
                raise BuildError("unsupported config.status statement; configure and rebuild the base")
        if (set(values) != allowed or import_count != 1 or main_count > 1
                or values.get("__all__") != ["topobjdir", "topsrcdir", "defines", "substs", "mozconfig"]
                or values.get("mozconfig") != str(context.mozconfig)
                or values.get("topobjdir") != str(context.objdir)
                or values.get("topsrcdir") != str(SOURCE)
                or not isinstance(values.get("substs"), dict)
                or not context.configured_safebrowsing_key_matches(
                    values["substs"].get("MOZ_GOOGLE_SAFEBROWSING_API_KEY"))):
            raise BuildError("base configuration does not bind the verified Safe Browsing key; configure and rebuild the base")
    except (ValueError, TypeError, SyntaxError, UnicodeError, RecursionError, MemoryError):
        raise BuildError("unsupported config.status shape; configure and rebuild the base") from None
    return config_hash


def base_package_evidence(context: HostBuildContext, package: Path) -> dict:
    return {"schema_version": 1, "kind": "verified-safebrowsing-base-package",
            "inputs": context.safebrowsing_evidence(),
            "config_status_sha256": verify_configured_key(context),
            "source_marker_sha256": file_digest(SOURCE / ".good-bear-materialization.json", maximum=1048576),
            "base_package": str(package), "base_package_sha256": file_digest(package)}


def record_base_package(context: HostBuildContext, package: Path) -> None:
    """Called only after this invocation's build and package both succeeded."""
    evidence = base_package_evidence(context, package)
    target = context.private_input_dir / "base-package-binding.json"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=context.private_input_dir,
                                         prefix="base-binding-", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(evidence, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def verify_repack_base(context: HostBuildContext) -> Path:
    package = find_base_package(context.objdir)
    receipt = context.private_input_dir / "base-package-binding.json"
    try:
        file_digest(receipt, maximum=65536)
        evidence = json.loads(receipt.read_bytes())
    except (OSError, ValueError, BuildError):
        raise BuildError("repack-only lacks verified base evidence; configure and rebuild the base") from None
    if evidence != base_package_evidence(context, package):
        raise BuildError("repack base inputs changed; configure and rebuild the base")
    return package


def russian_repack_environment(environment: dict[str, str]) -> dict[str, str]:
    """Apply Good Bear's release-locale boundary only to the RU repack."""
    return environment | {"GOODBEAR_RUSSIAN_ONLY": "1"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objdir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--safebrowsing-key-file", type=Path, required=True,
                        help="explicit external private key file matching the supplier input contract")
    parser.add_argument(
        "--release-lto",
        action="store_true",
        help="use the sole approved M13-06 full-LTO host configuration",
    )
    parser.add_argument(
        "--repack-only",
        action="store_true",
        help="reuse the existing base package and run only the Russian repack",
    )
    parser.add_argument(
        "--configure",
        action="store_true",
        help="force configuration before the base build",
    )
    args = parser.parse_args()
    try:
        context = HostBuildContext.create(args.objdir, release_lto=args.release_lto)
        context = context.with_safebrowsing_key(args.safebrowsing_key_file)
        context.validate()
        reject_conflicting_toolchain_environment(dict(os.environ))
        print(context.render("russian-repack"), flush=True)
        environment = context.environment()
        print("==> wasm2c host C++ ABI preflight", flush=True)
        wasm2c_host_cpp_probe(Path(environment["CXX"]), environment)
        if not RUSSIAN_PKI_BUILD_INPUT_DIR.is_dir():
            raise BuildError(
                "missing verified M3 Russian PKI build inputs; run the controlled "
                "certificate import before building"
            )
        print("==> M3-04 Russian PKI build-input verification", flush=True)
        verify_russian_pki_build_inputs(RUSSIAN_PKI_BUILD_INPUT_DIR.resolve())
        environment["GOODBEAR_RUSSIAN_PKI_BUILD_INPUT_DIR"] = str(
            RUSSIAN_PKI_BUILD_INPUT_DIR.resolve()
        )
        if args.repack_only:
            environment["GOODBEAR_BASE_PACKAGE"] = str(verify_repack_base(context))
            print("==> repack the only shipped locale: ru", flush=True)
            run(("build", "installers-ru"), russian_repack_environment(environment), context=context)
            print("Russian Good Bear host candidate completed", flush=True)
            return 0
        configure = args.configure or requires_initial_configure(context.objdir)
        if not configure:
            try:
                verify_configured_key(context)
            except BuildError:
                configure = True
        # A failed or interrupted new base build must not retain an old receipt.
        (context.private_input_dir / "base-package-binding.json").unlink(missing_ok=True)
        if not configure:
            print("==> reuse existing Firefox configuration", flush=True)
        for phase, command in command_plan(args.jobs, configure=configure):
            print(f"==> {phase}", flush=True)
            if command != ("configure",):
                verify_configured_key(context)
            if command == ("build", "installers-ru"):
                verify_repack_base(context)
                run(command, russian_repack_environment(environment), context=context)
            else:
                run(command, environment, context=context)
            if command == ("configure",):
                verify_configured_key(context)
            if command == ("package",):
                package = stage_base_inputs(context.objdir)
                record_base_package(context, package)
                environment["GOODBEAR_BASE_PACKAGE"] = str(package)
            if command == ("build", "installers-ru"):
                stage_en_us_outputs(context.objdir)
    except (BuildError, BuildInputError, ContextError, PreflightError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Russian Good Bear host candidate completed", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
