from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "m15_03_configure_windows_winrm.ps1"


def test_bootstrap_is_https_only_and_never_enables_basic_or_unencrypted_winrm():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "-Transport HTTPS" in text
    assert "-LocalPort 5986" in text
    assert "Service\\AllowUnencrypted -Value $false" in text
    assert "Service\\Auth\\Basic -Value $false" in text
    assert "Service\\Auth\\CredSSP -Value $false" in text
    assert "Transport=HTTP" in text and "Remove-Item -Recurse -Force" in text


def test_bootstrap_requires_an_exact_source_address_and_records_redactable_evidence():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "[string]$AllowedSourceCidr" in text
    assert "/32$" in text
    assert "-RemoteAddress $AllowedSourceCidr" in text
    assert "winrm-bootstrap.json" in text
    assert "GOOD_BEAR_WINRM_READY" in text
    assert "[Security.SecureString]$BuildUserPassword" in text
    assert "New-LocalUser -Name $BuildUser -Password $BuildUserPassword" in text
    assert "Stephenking1!" not in text
    assert "secret" not in text.lower()


def test_bootstrap_does_not_enable_rdp_or_create_an_unknown_account():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "Get-LocalUser -Name $BuildUser" in text
    assert "New-LocalUser -Name $BuildUser -Password $BuildUserPassword" in text
    assert "-LocalPort 3389" not in text
    assert "Enable-NetFirewallRule" not in text
