#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HOST_MOZCONFIG = ROOT / "build" / "ubuntu" / "mozconfig.host"
RELEASE_LTO_MOZCONFIG = ROOT / "build" / "ubuntu" / "mozconfig.release-lto"


class HostWasiMozconfigTest(unittest.TestCase):
    def test_host_build_uses_pinned_wasi_sdk_for_rlbox_cpp(self) -> None:
        mozconfig = HOST_MOZCONFIG.read_text(encoding="utf-8")

        self.assertIn(
            'ac_add_options --with-wasi-sysroot="$goodbear_wasi_sdk/share/wasi-sysroot"',
            mozconfig,
        )
        self.assertIn('export WASI_SYSROOT="$goodbear_wasi_sdk/share/wasi-sysroot"', mozconfig)
        self.assertIn('export WASM_CC="$goodbear_wasi_sdk/bin/clang"', mozconfig)
        self.assertIn('export WASM_CXX="$goodbear_wasi_sdk/bin/clang++"', mozconfig)
        self.assertIn(
            'export CBINDGEN="$goodbear_root/artifacts/toolchains/current/cbindgen/bin/cbindgen"',
            mozconfig,
        )
        self.assertIn("mk_add_options MOZ_CO_LOCALES=ru", mozconfig)
        self.assertNotIn("--enable-ui-locale=ru", mozconfig)
        self.assertNotIn("--without-wasm-sandboxed-libraries", mozconfig)

    def test_release_lto_config_keeps_wasi_and_forbids_non_release_fallback(self) -> None:
        mozconfig = RELEASE_LTO_MOZCONFIG.read_text(encoding="utf-8")
        self.assertIn("ac_add_options --enable-release", mozconfig)
        self.assertIn("export MOZ_LTO=full", mozconfig)
        self.assertNotIn("--disable-release", mozconfig)
        self.assertNotIn("unset MOZ_LTO", mozconfig)
        self.assertIn('export WASM_CXX="$goodbear_wasi_sdk/bin/clang++"', mozconfig)


if __name__ == "__main__":
    unittest.main()
