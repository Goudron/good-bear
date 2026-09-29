#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ubuntu_environment", ROOT / "tools" / "verify_ubuntu_environment.py")
assert SPEC and SPEC.loader
ENVIRONMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENVIRONMENT)


class UbuntuEnvironmentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads((ROOT / "config" / "ubuntu-environment-lock.json").read_text(encoding="utf-8"))

    def test_repository_environment_lock_is_consistent(self) -> None:
        ENVIRONMENT.verify(self.lock)

    def test_cxx_abi_package_closure_is_directly_pinned_for_provisioning(self) -> None:
        packages = self.lock["apt"]["direct_packages"]
        self.assertEqual(packages["build-essential"], "12.10ubuntu1")
        self.assertEqual(packages["g++"], "4:13.2.0-7ubuntu1")
        self.assertEqual(packages["g++-13"], packages["libstdc++-13-dev"])
        installer = (ROOT / "build" / "ubuntu" / "install-packages.sh").read_text(encoding="utf-8")
        for package in ("build-essential", "g++", "g++-13", "libstdc++-13-dev"):
            self.assertIn(f"{package}={packages[package]}", installer)

    def test_builder_bootstrap_is_idempotent_without_mutating_existing_account(self) -> None:
        installer = (ROOT / "build" / "ubuntu" / "install-packages.sh").read_text(encoding="utf-8")
        self.assertIn("if ! builder_entry=$(getent passwd builder); then", installer)
        self.assertIn("useradd --create-home --shell /bin/bash builder", installer)
        self.assertIn('builder_home=$(printf \'%s\\n\' "$builder_entry" | cut -d: -f6)', installer)
        self.assertIn('builder_shell=$(printf \'%s\\n\' "$builder_entry" | cut -d: -f7)', installer)
        self.assertIn('builder_home" = "/home/builder"', installer)
        self.assertIn('builder_shell" = "/bin/bash"', installer)

    def test_rejects_incomplete_cxx_abi_package_closure(self) -> None:
        del self.lock["apt"]["direct_packages"]["libstdc++-13-dev"]
        with self.assertRaisesRegex(ENVIRONMENT.EnvironmentError, "libstdc\\+\\+-13-dev"):
            ENVIRONMENT.verify(self.lock)

    def test_rejects_an_english_release_locale(self) -> None:
        self.lock["target"]["release_locale"] = "en-US"
        with self.assertRaisesRegex(ENVIRONMENT.EnvironmentError, "Russian-only"):
            ENVIRONMENT.verify(self.lock)

    def test_rejects_a_floating_oci_base_image(self) -> None:
        self.lock["oci"]["reference"] = "docker.io/library/ubuntu:24.04"
        with self.assertRaisesRegex(ENVIRONMENT.EnvironmentError, "exact official"):
            ENVIRONMENT.verify(self.lock)

    def test_rejects_disabling_wasm_sandboxed_libraries(self) -> None:
        with self.assertRaisesRegex(ENVIRONMENT.EnvironmentError, "must not disable"):
            ENVIRONMENT.verify(
                self.lock,
                ". $topsrcdir/build/goodbear/mozconfig\n"
                "ac_add_options --without-wasm-sandboxed-libraries\n",
            )

    def test_rejects_mozconfig_without_pinned_wasi_sysroot(self) -> None:
        with self.assertRaisesRegex(ENVIRONMENT.EnvironmentError, "pinned target WASI sysroot"):
            ENVIRONMENT.verify(
                self.lock,
                ". $topsrcdir/build/goodbear/mozconfig\n"
                "mk_add_options MOZ_CO_LOCALES=ru\n"
                "ac_add_options --with-l10n-base=/workspace/source/l10n/firefox-l10n\n"
                "ac_add_options --enable-ui-locale=ru\n"
                "ac_add_options --enable-application=browser\n",
            )

    def test_rejects_mozconfig_without_russian_ui_locale(self) -> None:
        with self.assertRaisesRegex(ENVIRONMENT.EnvironmentError, "start the candidate in Russian"):
            ENVIRONMENT.verify(
                self.lock,
                ". $topsrcdir/build/goodbear/mozconfig\n"
                "ac_add_options --with-wasi-sysroot=/workspace/toolchains/current/wasi-sdk/share/wasi-sysroot\n"
                "mk_add_options MOZ_CO_LOCALES=ru\n"
                "ac_add_options --with-l10n-base=/workspace/source/l10n/firefox-l10n\n",
            )

    def test_rejects_mozconfig_without_russian_shipped_locale(self) -> None:
        with self.assertRaisesRegex(ENVIRONMENT.EnvironmentError, "sole shipped locale"):
            ENVIRONMENT.verify(
                self.lock,
                ". $topsrcdir/build/goodbear/mozconfig\n"
                "ac_add_options --with-wasi-sysroot=/workspace/toolchains/current/wasi-sdk/share/wasi-sysroot\n"
                "ac_add_options --enable-ui-locale=ru\n"
                "ac_add_options --with-l10n-base=/workspace/source/l10n/firefox-l10n\n",
            )

    def test_rejects_unofficial_firefox_branding(self) -> None:
        with self.assertRaisesRegex(ENVIRONMENT.EnvironmentError, "unofficial Firefox branding"):
            ENVIRONMENT.verify(
                self.lock,
                ". $topsrcdir/build/goodbear/mozconfig\n"
                "ac_add_options --with-branding=browser/branding/unofficial\n"
                "ac_add_options --with-wasi-sysroot=/workspace/toolchains/current/wasi-sdk/share/wasi-sysroot\n",
            )


if __name__ == "__main__":
    unittest.main()
