#!/usr/bin/env python3
"""Focused structural tests for the Windows-side M15-03 VirtIO gate."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import generate_m15_03_windows_signature_gate as GATE  # noqa: E402


class M1503WindowsSignatureGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.script = GATE.render_gate()

    def test_pins_only_server_2025_amd64_driver_bundles(self) -> None:
        self.assertEqual(GATE.DRIVER_BUNDLES, (
            ("vioscsi", "vioscsi.cat", ("vioscsi.inf", "vioscsi.sys")),
            ("NetKVM", "netkvm.cat", ("netkvm.inf", "netkvm.sys", "netkvmp.exe")),
        ))
        self.assertIn("\\2k25\\amd64", self.script)
        self.assertNotIn("w10", self.script.lower())
        self.assertNotIn("w11", self.script.lower())
        self.assertIn("'netkvmp.exe'", self.script)

    def test_uses_kernel_policy_catalog_membership_for_inf_and_sys(self) -> None:
        self.assertIn("@('verify', '/kp', '/v', $Catalog)", self.script)
        self.assertIn("@('verify', '/kp', '/v', '/c', $Catalog, $File)", self.script)
        self.assertIn("<CAT> <INF-or-SYS>", self.script)
        self.assertIn("passed_catalog_signature", self.script)
        self.assertIn("passed_catalog_membership", self.script)

    def test_evidence_is_atomic_and_has_only_nonsecret_record_fields(self) -> None:
        self.assertIn("Get-FileHash -Algorithm SHA256", self.script)
        self.assertIn("path = $Path; sha256 = $Sha256; result = $Result", self.script)
        self.assertIn("[System.IO.File]::WriteAllText", self.script)
        self.assertIn("Move-Item -LiteralPath $temporary -Destination $destination", self.script)
        self.assertIn("refusing to overwrite existing signature-gate evidence", self.script)
        self.assertNotIn("token", self.script.lower())
        self.assertNotIn("credential", self.script.lower())

    def test_missing_or_failed_check_prevents_sysprep(self) -> None:
        self.assertIn("explicit signtool.exe is required before Sysprep", self.script)
        self.assertIn("[string]$SignTool", self.script)
        self.assertNotIn("Get-Command signtool.exe", self.script)
        self.assertIn("required VirtIO file is missing", self.script)
        self.assertIn("if ($LASTEXITCODE -ne 0)", self.script)
        self.assertIn("throw 'signtool verification failed'", self.script)
        self.assertIn("host-side catalog check is deliberately not accepted", self.script)
        self.assertIn("Add-Record $Catalog $hash 'failed'", self.script)
        self.assertIn("Add-Record $File $hash 'failed'", self.script)


if __name__ == "__main__":
    unittest.main()
