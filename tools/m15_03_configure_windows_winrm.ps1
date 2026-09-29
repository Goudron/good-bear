# GB100-M15-03 — one-time bootstrap for the approved Cloud.ru Windows Server 2022 VM.
#
# Run only from its Cloud.ru VNC console in an elevated PowerShell session.  This script
# creates an HTTPS-only WinRM endpoint for the exact maintainer source address.  It does
# not enable RDP, Basic authentication, unencrypted WinRM, or any public ingress.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^([0-9]{1,3}\.){3}[0-9]{1,3}/32$')]
    [string]$AllowedSourceCidr,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^([0-9]{1,3}\.){3}[0-9]{1,3}$')]
    [string]$PublicIp,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$BuildUser,

    [Parameter(Mandatory = $true)]
    [Security.SecureString]$BuildUserPassword
)

$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this bootstrap from an elevated Administrator PowerShell session.'
}

if (-not (Get-LocalUser -Name $BuildUser -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $BuildUser -Password $BuildUserPassword -AccountNeverExpires -Description 'Good Bear isolated build account' | Out-Null
}

Add-LocalGroupMember -Group 'Administrators' -Member $BuildUser -ErrorAction SilentlyContinue
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM
Enable-PSRemoting -SkipNetworkProfileCheck -Force

$cert = New-SelfSignedCertificate `
    -Type SSLServerAuthentication `
    -Subject "CN=$PublicIp" `
    -DnsName $PublicIp `
    -CertStoreLocation 'Cert:\LocalMachine\My' `
    -FriendlyName 'Good Bear M15-03 WinRM' `
    -KeyExportPolicy NonExportable `
    -NotAfter (Get-Date).AddYears(1)

# The HTTP listener created by Enable-PSRemoting is intentionally removed only after
# the authenticated HTTPS listener exists.
Get-ChildItem -Path WSMan:\localhost\Listener | Where-Object { $_.Keys -match 'Transport=HTTPS' } |
    Remove-Item -Recurse -Force
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address '*' -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null
Get-ChildItem -Path WSMan:\localhost\Listener | Where-Object { $_.Keys -match 'Transport=HTTP' } |
    Remove-Item -Recurse -Force

Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $false
Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $false
Set-Item -Path WSMan:\localhost\Service\Auth\Kerberos -Value $true
Set-Item -Path WSMan:\localhost\Service\Auth\Negotiate -Value $true

$ruleName = 'Good Bear M15-03 WinRM HTTPS from maintainer'
Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP `
    -LocalPort 5986 -RemoteAddress $AllowedSourceCidr -Profile Any | Out-Null

$evidenceDirectory = 'C:\ProgramData\GoodBear\M15-03'
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
@{
    schema_version = 1
    configured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    build_user = $BuildUser
    allowed_source_cidr = $AllowedSourceCidr
    winrm_transport = 'HTTPS'
    winrm_port = 5986
    certificate_sha1_thumbprint = $cert.Thumbprint
    basic_authentication = $false
    unencrypted_transport = $false
    rdp_enabled_by_this_script = $false
} | ConvertTo-Json | Set-Content -Path "$evidenceDirectory\winrm-bootstrap.json" -Encoding UTF8 -NoNewline

Write-Output "GOOD_BEAR_WINRM_READY thumbprint=$($cert.Thumbprint) port=5986"
