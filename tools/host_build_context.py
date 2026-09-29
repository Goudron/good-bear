#!/usr/bin/env python3
"""Resolve and validate the one supported local Good Bear host-build context."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
import stat
import sys

from project_temp import build_temp_dir
from safebrowsing_build_input import (
    BuildInputError, EffectiveMozconfig, SHA256, create_effective_mozconfig,
    verify_effective_mozconfig, verify_key_file,
)


ROOT = Path(__file__).resolve().parents[1]
FIREFOX_BASELINE = ROOT / "config" / "firefox-baseline.json"
SAFEBROWSING_CONTRACT = ROOT / "config" / "m15-12-safebrowsing-build-input.json"


def _baseline_worktree_name() -> str:
    """Return the single materialized Firefox worktree declared by the baseline.

    Build entry points must not silently retain an earlier worktree when the
    verified upstream baseline changes.  Keep the directory name derived from
    the reviewed baseline, but reject path-shaped values rather than allowing a
    configuration error to escape the project worktree root.
    """
    try:
        baseline = json.loads(FIREFOX_BASELINE.read_text(encoding="utf-8"))
        version = baseline["version"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RuntimeError(f"cannot read Firefox baseline version: {exc}") from exc
    if not isinstance(version, str) or not version or Path(version).name != version:
        raise RuntimeError("Firefox baseline version is not a safe worktree name")
    return f"firefox-{version}"


FIREFOX_WORKTREE_NAME = _baseline_worktree_name()
SOURCE = ROOT / "source" / "worktrees" / FIREFOX_WORKTREE_NAME
MOZCONFIG = ROOT / "build" / "ubuntu" / "mozconfig.host"
RELEASE_LTO_MOZCONFIG = ROOT / "build" / "ubuntu" / "mozconfig.release-lto"
L10N_BASE = ROOT / "source" / "l10n" / "firefox-l10n"
TOOLCHAIN = ROOT / "artifacts" / "toolchains" / "current"
TOOLCHAIN_LOCK = ROOT / "config" / "toolchain-lock.json"
ARTIFACTS = ROOT / "artifacts"

INTENTS = {
    "engine-test": (
        "internal Firefox base binary; not Russian UI evidence",
        "en-US input only",
    ),
    "russian-repack": (
        "Russian-only Good Bear language repack candidate",
        "ru",
    ),
    "localized-smoke": (
        "Russian-only Good Bear artifact smoke",
        "ru",
    ),
}


class ContextError(RuntimeError):
    pass


# Keep these bindings explicit.  Firefox's build system also discovers LLVM
# helpers such as llvm-objdump through PATH, so only the locked LLVM bin
# directory is prepended there; the compiler and all other owned tools are
# bound by their absolute verified paths below.
TOOLCHAIN_EXECUTABLES = {
    "CC": ("locked LLVM compiler", Path("llvm/bin/clang")),
    "CXX": ("locked LLVM C++ compiler", Path("llvm/bin/clang++")),
    "RUSTC": ("locked Rust compiler", Path("rust/bin/rustc")),
    "CARGO": ("locked Cargo", Path("rust/bin/cargo")),
    "NODEJS": ("locked Node.js", Path("node/bin/node")),
    "CBINDGEN": ("locked cbindgen", Path("cbindgen/bin/cbindgen")),
}
REQUIRED_LLVM_EXECUTABLES = {
    "locked LLVM compiler": Path("llvm/bin/clang"),
    "locked LLVM C++ compiler": Path("llvm/bin/clang++"),
    "locked LLVM linker": Path("llvm/bin/lld"),
    "locked LLVM object inspector": Path("llvm/bin/llvm-objdump"),
}

# A remote builder must not inherit a compiler choice or flags from its image,
# login shell, or transport wrapper.  `environment()` removes these values and
# supplies the reviewed values below; the build entry point rejects a nonempty
# inherited value so a configuration mistake is visible rather than silently
# hidden by the sanitisation.
CONFLICTING_TOOLCHAIN_ENV = ("CC", "CXX", "LD", "CXXFLAGS", "LDFLAGS")
HOST_CXX_LINK_FLAGS = "-fuse-ld=lld"


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def conflicting_toolchain_environment(environment: dict[str, str]) -> tuple[str, ...]:
    """Return inherited compiler variables that the host build must reject."""
    return tuple(
        variable for variable in CONFLICTING_TOOLCHAIN_ENV
        if environment.get(variable)
    )


def reject_conflicting_toolchain_environment(environment: dict[str, str]) -> None:
    conflicts = conflicting_toolchain_environment(environment)
    if conflicts:
        raise ContextError(
            "conflicting inherited host toolchain environment: " + ", ".join(conflicts)
        )


def _toolchain_marker() -> dict[str, object]:
    try:
        lock_bytes = TOOLCHAIN_LOCK.read_bytes()
        lock = json.loads(lock_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContextError(f"cannot read pinned toolchain lock: {exc}") from exc
    if not isinstance(lock, dict) or not isinstance(lock.get("components"), list):
        raise ContextError("pinned toolchain lock is malformed")
    try:
        components = [
            {
                "id": component["id"],
                "version": component["version"],
                "archive_sha256": component["archive"]["sha256"],
            }
            for component in lock["components"]
        ]
        target = lock["target"]
    except (KeyError, TypeError) as exc:
        raise ContextError("pinned toolchain lock is malformed") from exc
    if not isinstance(target, str) or not all(
        isinstance(component["id"], str)
        and isinstance(component["version"], str)
        and isinstance(component["archive_sha256"], str)
        for component in components
    ):
        raise ContextError("pinned toolchain lock is malformed")
    return {
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "target": target,
        "components": components,
    }


def _verified_toolchain_executables() -> dict[str, Path]:
    try:
        marker = json.loads(
            (TOOLCHAIN / ".good-bear-toolchain.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ContextError(f"missing or unreadable pinned toolchain marker: {exc}") from exc
    if marker != _toolchain_marker():
        raise ContextError("pinned toolchain marker does not match the current lock")

    prefix = TOOLCHAIN.resolve()
    required = dict(REQUIRED_LLVM_EXECUTABLES)
    required.update({label: relative for label, relative in TOOLCHAIN_EXECUTABLES.values()})
    resolved: dict[str, Path] = {}
    for label, relative in required.items():
        executable = TOOLCHAIN / relative
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ContextError(f"missing executable {label}: {executable}")
        real_executable = executable.resolve()
        if not _under(real_executable, prefix):
            raise ContextError(f"toolchain executable escapes pinned prefix: {executable}")
        # Retain the declared executable spelling after validating its target.
        # clang selects C++ driver behaviour from argv[0]; returning the
        # resolved clang++ symlink target (`clang-22`) would make a C++ link
        # omit the driver's implicit libstdc++ argument.
        resolved[relative.as_posix()] = executable
    return resolved


def load_safebrowsing_contract() -> tuple[dict, str]:
    try:
        if SAFEBROWSING_CONTRACT.is_symlink() or not SAFEBROWSING_CONTRACT.is_file():
            raise ContextError("Safe Browsing supplier contract is unavailable")
        with SAFEBROWSING_CONTRACT.open("rb") as stream:
            data = stream.read(65537)
        if len(data) > 65536:
            raise ContextError("Safe Browsing supplier contract exceeds its size bound")
        contract = json.loads(data)
        if (contract.get("schema_version") != 1 or contract.get("task") != "GB100-M15-12"
                or contract.get("supplier") != "Google Safe Browsing"
                or contract.get("allowed_api_services") != ["safebrowsing.googleapis.com"]
                or contract.get("key_value_in_source") is not False
                or contract.get("key_value_in_build_logs") is not False
                or not isinstance(contract.get("key_file_sha256"), str)
                or SHA256.fullmatch(contract["key_file_sha256"]) is None):
            raise ContextError("Safe Browsing supplier contract is invalid")
        return contract, hashlib.sha256(data).hexdigest()
    except (OSError, ValueError, TypeError, AttributeError):
        raise ContextError("Safe Browsing supplier contract could not be read safely") from None


@dataclass(frozen=True)
class HostBuildContext:
    objdir: Path
    release_lto: bool = False
    _safebrowsing: EffectiveMozconfig | None = field(default=None, repr=False)
    _supplier_contract_sha256: str | None = field(default=None, repr=False)

    @classmethod
    def create(cls, objdir: Path, *, release_lto: bool = False) -> "HostBuildContext":
        resolved = objdir.resolve()
        if not _under(resolved, ARTIFACTS.resolve()):
            raise ContextError("object directory must stay under artifacts/")
        return cls(resolved, release_lto=release_lto)

    @property
    def base_mozconfig(self) -> Path:
        return RELEASE_LTO_MOZCONFIG if self.release_lto else MOZCONFIG

    @property
    def mozconfig(self) -> Path:
        return self._safebrowsing.path if self._safebrowsing else self.base_mozconfig

    @property
    def private_input_dir(self) -> Path:
        return self.objdir / ".goodbear-private-inputs"

    def with_safebrowsing_key(self, key_file: Path) -> "HostBuildContext":
        if os.name != "posix":
            raise ContextError("the Ubuntu private build context requires a native POSIX host")
        contract, contract_hash = load_safebrowsing_contract()
        key = verify_key_file(key_file, contract["key_file_sha256"],
                              forbidden_roots=(ROOT, SOURCE))
        self.objdir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.objdir.is_symlink() or self.objdir.stat().st_uid != os.geteuid():
            raise ContextError("key-bearing object directory requires the build owner")
        # Firefox writes the key into generated config.status and object data.
        # Restrict the entire object directory before configure can create them.
        self.objdir.chmod(0o700)
        directory = self.private_input_dir
        if directory.is_symlink() or directory.resolve() != directory:
            raise ContextError("private build-input directory must not use symlinks")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = directory.stat()
        if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid():
            raise ContextError("private build-input directory requires owner-only permissions")
        try:
            base_hash = hashlib.sha256(self.base_mozconfig.read_bytes()).hexdigest()
        except OSError:
            raise ContextError("canonical base mozconfig is unavailable") from None
        # Different inputs get a different stable path. Never overwrite a
        # wrapper that a previous config.status still references.
        wrapper = directory / f"mozconfig-{base_hash}-{key.sha256}"
        binding = create_effective_mozconfig(
            base_mozconfig=self.base_mozconfig, expected_base_sha256=base_hash,
            key_input=key, wrapper_path=wrapper, source_root=SOURCE, reuse_verified=True)
        return replace(self, _safebrowsing=binding, _supplier_contract_sha256=contract_hash)

    def validate_safebrowsing(self) -> None:
        if self._safebrowsing is None:
            raise ContextError("Russian builds require an explicit verified Safe Browsing key file")
        for directory in (self.objdir, self.private_input_dir):
            if (directory.is_symlink() or stat.S_IMODE(directory.stat().st_mode) != 0o700
                    or directory.stat().st_uid != os.geteuid()):
                raise ContextError("key-bearing build directories require owner-only permissions")
        contract, digest = load_safebrowsing_contract()
        if digest != self._supplier_contract_sha256 or contract["key_file_sha256"] != self._safebrowsing.key_sha256:
            raise ContextError("Safe Browsing supplier input changed; prepare a new build binding")
        if self._safebrowsing.base_path != self.base_mozconfig or self._safebrowsing.path.parent != self.private_input_dir:
            raise ContextError("effective mozconfig is outside the canonical build context")
        verify_effective_mozconfig(self._safebrowsing)

    def safebrowsing_evidence(self) -> dict[str, str]:
        self.validate_safebrowsing()
        return self._safebrowsing.evidence() | {"supplier_contract_sha256": self._supplier_contract_sha256}

    def safebrowsing_log_redactor(self):
        self.validate_safebrowsing()
        return self._safebrowsing._key_input.log_redactor()

    def configured_safebrowsing_key_matches(self, value: object) -> bool:
        self.validate_safebrowsing()
        return self._safebrowsing._key_input.matches_configured_key(value)

    def validate(self) -> None:
        required = {
            "Firefox worktree": SOURCE,
            "host mozconfig": self.mozconfig,
            "pinned l10n base": L10N_BASE,
            "pinned toolchain": TOOLCHAIN,
        }
        for label, path in required.items():
            if not path.exists():
                raise ContextError(f"missing {label}: {path}")
        if not (SOURCE / "mach").is_file():
            raise ContextError(f"Firefox worktree has no mach: {SOURCE}")
        _verified_toolchain_executables()
        if self._safebrowsing:
            self.validate_safebrowsing()

    def environment(self) -> dict[str, str]:
        if self._safebrowsing:
            self.validate_safebrowsing()
        executables = _verified_toolchain_executables()
        llvm_bin = TOOLCHAIN.resolve() / "llvm" / "bin"
        # Do this even for callers which did not use the build entry point.
        # A canonical environment must never retain a foreign compiler or
        # linker flag.
        inherited = {
            variable: value for variable, value in os.environ.items()
            if variable not in CONFLICTING_TOOLCHAIN_ENV and variable not in {
                "MOZ_CONFIGURE_OPTIONS", "MOZ_GOOGLE_SAFEBROWSING_API_KEY",
                "GOODBEAR_SAFEBROWSING_KEY_FILE",
            }
        }
        return inherited | {
            "MOZCONFIG": str(self.mozconfig),
            "MOZ_OBJDIR": str(self.objdir),
            "PATH": str(llvm_bin) + os.pathsep + os.environ.get("PATH", ""),
            **{
                variable: str(executables[relative.as_posix()])
                for variable, (_, relative) in TOOLCHAIN_EXECUTABLES.items()
            },
            "LD": str(executables["llvm/bin/lld"]),
            # Keep CXX a path, not a shell fragment.  The driver receives this
            # link choice through the normal flags channel and the preflight
            # below proves that clang++ actually selects lld and libstdc++.
            "LDFLAGS": HOST_CXX_LINK_FLAGS,
            # Rust and linker intermediates can be many GiB.  Keep them on the
            # project volume instead of the small system tmpfs.
            "TMPDIR": str(build_temp_dir()),
            "TMP": str(build_temp_dir()),
            "TEMP": str(build_temp_dir()),
        }

    def render(self, intent: str) -> str:
        if intent not in INTENTS:
            raise ContextError(f"unsupported intent: {intent}")
        description, claimed_locale = INTENTS[intent]
        rendered = "\n".join(
            (
                "==> Good Bear host context",
                f"intent: {intent} ({description})",
                f"project root: {ROOT}",
                f"Firefox source: {SOURCE}",
                f"object directory: {self.objdir}",
                f"MOZCONFIG: {self.mozconfig}",
                f"link-time optimization: {'full' if self.release_lto else 'disabled'}",
                f"l10n input: {L10N_BASE}",
                "base input locale: en-US (internal only)",
                f"claimed artifact locale: {claimed_locale}",
                "sole shipped locale: ru",
            )
        )
        if self._safebrowsing:
            evidence = self.safebrowsing_evidence()
            rendered += "\n" + "\n".join((
                f"base MOZCONFIG: {self.base_mozconfig}",
                *(f"{name}: {digest}" for name, digest in evidence.items()),
            ))
        return rendered


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objdir", type=Path, required=True)
    parser.add_argument("--intent", choices=sorted(INTENTS), required=True)
    parser.add_argument("--release-lto", action="store_true")
    args = parser.parse_args()
    try:
        context = HostBuildContext.create(args.objdir, release_lto=args.release_lto)
        context.validate()
        print(context.render(args.intent), flush=True)
    except ContextError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
