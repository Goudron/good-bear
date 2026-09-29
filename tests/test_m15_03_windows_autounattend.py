#!/usr/bin/env python3
"""Focused pre-artifact rejections for GB100-M15-03 autounattend inputs."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import generate_m15_03_autounattend as AUTO  # noqa: E402


class M1503AutounattendTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads((ROOT / "config" / "m15-03-windows-autounattend-lock.json").read_text(encoding="utf-8"))

    def test_pinned_iso_default_lock_keeps_virtio_untrusted_and_post_boot_only(self) -> None:
        iso = self.lock["inputs"]["windows_server_2025_eval_iso"]
        self.assertEqual(iso["path"], "/home/valery/Загрузки/26100.32230.260111-0550.lt_release_svc_refresh_SERVER_EVAL_x64FRE_ru-ru.iso")
        self.assertEqual(iso["sha256"], "0b1b0a94c330cbd660d5ed7a4fb843665f48935df7aa1eca8ac49e0504161deb")
        self.assertEqual(iso["observed_media_evidence"], {
            "udf_volume_id": "SSS_X64FREE_RU-RU_DV9",
            "wim_paths": ["sources/boot.wim", "sources/install.wim"],
            "ru_filename_evidence": "x64FRE_ru-ru.iso",
            "server_evaluation_filename_evidence": "SERVER_EVAL",
        })
        self.assertEqual(self.lock["inputs"]["cloudbase_init"], {
            "path": "/home/valery/.cache/goodbear-m15-03-inputs/CloudbaseInitSetup_1_1_8_x64.msi",
            "sha256": "0e7fa42e0cbc0ce7657f85730b0c6cc7afc4087a3639df0ff51a721a0be19bd5",
            "authenticode_verified": True,
            "publisher": "CN=Cloudbase Solutions Srl,O=Cloudbase Solutions Srl,L=Timisoara,C=RO",
            "official_source": "https://github.com/cloudbase/cloudbase-init/releases/download/1.1.8/CloudbaseInitSetup_1_1_8_x64.msi",
        })
        self.assertEqual(self.lock["inputs"]["virtio_win"], {
            "path": None,
            "sha256": None,
            "signature_verified": False,
            "media_volume_label": "virtio-win-0.1.302",
        })
        self.assertEqual(self.lock["windows"]["image_name"], "Windows Server 2025 Standard Evaluation")
        AUTO.validate_lock(self.lock, verify_files=False)

    def test_generate_missing_inputs_creates_no_destination(self) -> None:
        unready = copy.deepcopy(self.lock)
        unready["inputs"]["windows_server_2025_eval_iso"]["path"] = None
        unready["inputs"]["windows_server_2025_eval_iso"]["sha256"] = None
        destination = ROOT / "build" / f"m15-03-autounattend-rejected-{uuid.uuid4().hex}"
        self.assertFalse(destination.exists())
        with self.assertRaisesRegex(AUTO.AutounattendError, "existing pinned path"):
            AUTO.generate(unready, destination)
        self.assertFalse(destination.exists())

    def test_complete_pins_render_russian_server_core_with_resumable_ordered_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            changed = self._pinned_lock(root)
            xml, bootstrap, provenance, signature_gate = AUTO.render(changed)
            self.assertIn("ru-RU", xml)
            self.assertIn("Windows Server 2025 Standard Evaluation", xml)
            self.assertIn("<UseConfigurationSet>true</UseConfigurationSet>", xml)
            self.assertIn("<WillWipeDisk>true</WillWipeDisk>", xml)
            self.assertIn('<settings pass="specialize">', xml)
            self.assertIn('name="Microsoft-Windows-SQMAPI"', xml)
            self.assertIn("<CEIPEnabled>0</CEIPEnabled>", xml)
            self.assertNotIn("PnpCustomizationsWinPE", xml)
            self.assertNotIn("E:\\", xml)
            self.assertIn("Cloudbase", bootstrap)
            self.assertIn("OpenSSH.Server", bootstrap)
            self.assertIn("OpenSSH Server capability did not install", bootstrap)
            self.assertIn("GoodBear-M15-03-OpenSSH", bootstrap)
            self.assertIn("OpenSSH Server is not running with automatic start", bootstrap)
            self.assertIn("GoodBear-M15-03-Bootstrap", bootstrap)
            self.assertIn("/RU SYSTEM /RL HIGHEST", bootstrap)
            self.assertIn("schtasks.exe\" /Create", bootstrap)
            self.assertIn("/RU SYSTEM /RL HIGHEST", bootstrap)
            self.assertIn("<LogonType>InteractiveToken</LogonType>", bootstrap)
            self.assertIn("schtasks /RU SYSTEM", bootstrap)
            self.assertIn("Export-ScheduledTask -TaskName $TaskName", bootstrap)
            self.assertIn("Restart-For-Resume", bootstrap)
            self.assertLess(bootstrap.index("'windows_update' { Apply-WindowsUpdates $state }"), bootstrap.index("'signing_tools' { Install-SigningTools $state }"))
            self.assertLess(bootstrap.index("'signing_tools' { Install-SigningTools $state }"), bootstrap.index("'driver_gate' { Run-DriverGateAndPrepareSysprep $state }"))
            self.assertLess(bootstrap.index("'driver_gate' { Run-DriverGateAndPrepareSysprep $state }"), bootstrap.index("'sysprep' { Invoke-FinalSysprep $state; break }"))
            self.assertIn("OptionId.SigningTools", bootstrap)
            self.assertIn("Get-AuthenticodeSignature", bootstrap)
            self.assertIn("/Online /Add-Driver", bootstrap)
            self.assertIn("-SignTool $signTool.path", bootstrap)
            self.assertIn("Sysprep bypass blocked", bootstrap)
            self.assertIn("$CloudbaseFileName = 'cloudbase_init.bin'", bootstrap)
            self.assertIn("$CloudbaseExpectedSha256", bootstrap)
            self.assertIn("Get-CloudbaseEvidence", bootstrap)
            self.assertIn("Find-VerifiedVirtioMediaDrive", bootstrap)
            self.assertIn("virtio-win-0.1.302", bootstrap)
            self.assertNotIn("$MediaDrive =", bootstrap)
            self.assertNotIn("CloudbaseInitSetup_*.msi", bootstrap)
            self.assertIn("windows_sdk_auto_removal", json.dumps(provenance))
            self.assertIn("do NOT auto-uninstall Windows SDK", bootstrap)
            self.assertNotIn("winsdksetup.exe /uninstall", bootstrap)
            self.assertIn("while ($true)", bootstrap)
            self.assertIn("$state = Read-State", bootstrap)
            # The generated code may refer to the OS SecureString API while
            # rotating a one-shot recovery credential before Sysprep.  It must
            # never embed or serialize a credential value or an answer-file
            # AdministratorPassword field.
            combined = xml + bootstrap + signature_gate + json.dumps(provenance)
            self.assertNotIn("<AdministratorPassword>", combined)
            self.assertNotRegex(combined, r"(?i)(?:password|authorization|private[ _-]?key)\s*[:=]\s*['\"][^'\"]+")
            self.assertTrue(provenance["sensitive_material_absent"])
            self.assertTrue(provenance["windows_signature_gate"]["required_before_sysprep"])

    def test_tampered_pinned_input_rejects_before_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            changed = self._pinned_lock(root)
            Path(changed["inputs"]["cloudbase_init"]["path"]).write_bytes(b"tampered")
            with self.assertRaisesRegex(AUTO.AutounattendError, "SHA-256 mismatch"):
                AUTO.render(changed)

    def test_complete_pins_emit_the_required_windows_signature_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            changed = self._pinned_lock(root)
            destination = ROOT / "build" / f"m15-03-autounattend-test-{uuid.uuid4().hex}"
            try:
                AUTO.generate(changed, destination)
                gate = (destination / "verify-virtio-signatures.ps1").read_text(encoding="utf-8")
                self.assertIn("signtool.exe", gate)
                self.assertIn("/c', $Catalog, $File", gate)
                self.assertIn("2k25\\amd64", gate)
                self.assertIn("[string]$SignTool", gate)
            finally:
                if destination.exists():
                    import shutil
                    shutil.rmtree(destination)

    def test_bootstrap_persists_reboot_state_before_each_supported_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, bootstrap, _, _ = AUTO.render(self._pinned_lock(Path(temporary)))
        self.assertIn("$State.phase = $NextPhase", bootstrap)
        self.assertIn("Save-State $State; Restart-Computer -Force", bootstrap)
        self.assertIn("if ($process.ExitCode -eq 3010) { Restart-For-Resume $State 'driver_gate' }", bootstrap)
        self.assertIn("if ($result.RebootRequired) { Restart-For-Resume $State 'windows_update' }", bootstrap)
        self.assertIn("Require ($process.ExitCode -eq 0)", bootstrap)
        self.assertNotIn("ExitCode -eq 1641", bootstrap)

    def test_windows_update_is_bounded_and_retries_without_skipping_updates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, bootstrap, _, _ = AUTO.render(self._pinned_lock(Path(temporary)))
        self.assertIn("$WindowsUpdateOperationTimeoutSeconds = 3600", bootstrap)
        self.assertIn("function Start-WindowsUpdateWatchdog", bootstrap)
        self.assertIn("Start-Job -ScriptBlock", bootstrap)
        self.assertIn("Restart-Computer -Force", bootstrap)
        self.assertIn("Windows Update exceeded the bounded recovery limit", bootstrap)
        self.assertIn("recovered_after_unfinished_attempt", bootstrap)
        self.assertIn("$search = $session.CreateUpdateSearcher().Search", bootstrap)
        self.assertIn("$download = $downloader.Download()", bootstrap)
        self.assertIn("$result = $installer.Install()", bootstrap)

    def test_sysprep_has_no_bypass_around_signing_gate_and_dism(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, bootstrap, _, _ = AUTO.render(self._pinned_lock(Path(temporary)))
        self.assertIn("Require ($State.phase -eq 'sysprep') 'Sysprep bypass blocked'", bootstrap)
        self.assertIn("'VirtIO signature evidence is absent'", bootstrap)
        self.assertLess(bootstrap.index("Find-VerifiedVirtioMediaDrive"), bootstrap.index("& $GatePath -MediaDrive"))
        self.assertLess(bootstrap.index("& $GatePath -MediaDrive"), bootstrap.index("Inject-VerifiedVirtioDrivers $State $mediaDrive"))
        self.assertLess(bootstrap.index("Inject-VerifiedVirtioDrivers $State $mediaDrive"), bootstrap.index("$State.phase = 'sysprep'"))
        self.assertLess(bootstrap.index("$State.phase = 'sysprep'"), bootstrap.index("function Invoke-FinalSysprep"))
        self.assertIn("function Rotate-RecoveryCredentialBeforeSysprep", bootstrap)
        self.assertIn("Set-LocalUser -InputObject $accounts[0] -Password $secure", bootstrap)
        self.assertIn("credential_value_recorded = $false", bootstrap)
        self.assertNotIn("net.exe user", bootstrap)
        self.assertLess(bootstrap.index("Rotate-RecoveryCredentialBeforeSysprep $State"), bootstrap.index("$State.phase = 'sysprep_requested'; Save-State $State"))
        self.assertLess(bootstrap.index("$State.phase = 'sysprep_requested'; Save-State $State"), bootstrap.index("Start-Process -FilePath \"$env:WINDIR\\System32\\Sysprep\\Sysprep.exe\""))
        self.assertLess(bootstrap.index("Require ($process.ExitCode -eq 0) 'Sysprep failed'"), bootstrap.index("Unregister-ScheduledTask -TaskName $TaskName"))
        self.assertIn("Sysprep was previously requested; refusing a second invocation", bootstrap)

    def test_rendered_cloudbase_msi_is_exactly_lock_pinned_before_msiexec(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            changed = self._pinned_lock(Path(temporary))
            cloudbase = changed["inputs"]["cloudbase_init"]
            cloudbase["path"] = str(Path(temporary) / "CloudbaseInitSetup_1_1_8_x64.msi")
            Path(cloudbase["path"]).write_bytes(b"cloudbase-locked")
            cloudbase["sha256"] = hashlib.sha256(Path(cloudbase["path"]).read_bytes()).hexdigest()
            cloudbase["publisher"] = "CN=Cloudbase Solutions Srl,O=Cloudbase Solutions Srl,L=Timisoara,C=RO"
            _, bootstrap, _, _ = AUTO.render(changed)
        self.assertIn("$CloudbaseFileName = 'CloudbaseInitSetup_1_1_8_x64.msi'", bootstrap)
        self.assertIn("$CloudbaseExpectedSha256 = '" + cloudbase["sha256"] + "'", bootstrap)
        self.assertIn("Cloudbase-Init MSI SHA-256 does not match the M15-03 lock", bootstrap)
        self.assertIn("Cloudbase-Init MSI publisher does not match the M15-03 lock", bootstrap)
        self.assertLess(bootstrap.index("Get-CloudbaseEvidence $cloudbase"), bootstrap.index("Start-Process -FilePath \"$env:WINDIR\\System32\\msiexec.exe\""))

    def test_secret_field_and_gui_drift_reject_before_artifact(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["administrator_password"] = "not-allowed"
        with self.assertRaisesRegex(AUTO.AutounattendError, "secret-like field"):
            AUTO.validate_lock(changed, verify_files=False)
        changed = copy.deepcopy(self.lock)
        changed["windows"]["gui"] = True
        with self.assertRaisesRegex(AUTO.AutounattendError, "Server Core"):
            AUTO.validate_lock(changed, verify_files=False)

    def test_diagnostic_data_policy_drift_rejects_before_artifact(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["privacy"]["ceip_enabled"] = 1
        with self.assertRaisesRegex(AUTO.AutounattendError, "diagnostic data"):
            AUTO.validate_lock(changed, verify_files=False)

    def _pinned_lock(self, root: Path) -> dict:
        changed = copy.deepcopy(self.lock)
        for index, name in enumerate(("windows_server_2025_eval_iso", "cloudbase_init"), 1):
            source = root / f"{name}.bin"
            source.write_bytes(f"input-{index}".encode())
            changed["inputs"][name]["path"] = str(source)
            changed["inputs"][name]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        changed["inputs"]["cloudbase_init"]["authenticode_verified"] = True
        changed["inputs"]["cloudbase_init"]["publisher"] = "Cloudbase Solutions"
        return changed


if __name__ == "__main__":
    unittest.main()
