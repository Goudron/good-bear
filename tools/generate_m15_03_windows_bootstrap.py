#!/usr/bin/env python3
"""Render the resumable, fail-closed Windows M15-03 bootstrap."""

from __future__ import annotations


# Official Microsoft 26100 SDK installer landing URL. Runtime code records the
# downloaded bytes and signature; HTTPS alone is never treated as a hash pin.
WINDOWS_SDK_INSTALLER_URL = "https://go.microsoft.com/fwlink/?linkid=2376216"
TASK_NAME = "GoodBear-M15-03-Bootstrap"
BOOTSTRAP_PATH = r"C:\GoodBear\first-boot.ps1"
GATE_PATH = r"C:\GoodBear\verify-virtio-signatures.ps1"
EVIDENCE_DIRECTORY = r"C:\ProgramData\GoodBear\m15-03-signature-evidence"
STATE_DIRECTORY = r"C:\ProgramData\GoodBear\m15-03-bootstrap"


def render_bootstrap(virtio_volume_label: str, cloudbase_filename: str, cloudbase_sha256: str,
                     cloudbase_publisher: str) -> str:
    """Return the secret-free SYSTEM state machine for the prepared guest."""
    return rf'''# GB100-M15-03: resumable, fail-closed pre-Sysprep bootstrap.
# This file must be staged at {BOOTSTRAP_PATH} by the configuration media.
# It accepts no secret material and no arbitrary URL.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$TaskName = '{TASK_NAME}'
$BootstrapPath = '{BOOTSTRAP_PATH}'
$GatePath = '{GATE_PATH}'
$VirtioVolumeLabel = '{virtio_volume_label}'
$EvidenceDirectory = '{EVIDENCE_DIRECTORY}'
$StateDirectory = '{STATE_DIRECTORY}'
$StatePath = Join-Path $StateDirectory 'state.json'
$SdkInstallerUrl = '{WINDOWS_SDK_INSTALLER_URL}'
$SdkInstallerPath = Join-Path $StateDirectory 'winsdksetup.exe'
$CloudbaseFileName = '{cloudbase_filename}'
$CloudbaseExpectedSha256 = '{cloudbase_sha256}'
$CloudbaseExpectedPublisher = '{cloudbase_publisher}'
$MaximumUpdatePasses = 8
$MaximumReboots = 8
$WindowsUpdateOperationTimeoutSeconds = 3600
$MaximumWindowsUpdateTimeoutRecoveries = 2

function Require([bool]$Condition, [string]$Message) {{
  if (-not $Condition) {{ throw $Message }}
}}

function Write-JsonAtomically([string]$Path, [object]$Value) {{
  $parent = Split-Path -Parent $Path
  New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
  $temporary = Join-Path $parent ('.' + [guid]::NewGuid().ToString('N') + '.tmp')
  try {{
    [System.IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 8 -Compress), [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $Path -Force -ErrorAction Stop
  }} finally {{
    if (Test-Path -LiteralPath $temporary) {{ Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }}
  }}
}}

function Read-State() {{
  if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {{
    return [ordered]@{{ schema_version = 1; phase = 'bootstrap'; reboot_count = 0; update_passes = 0; evidence = [ordered]@{{}} }}
  }}
  $state = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
  Require ($state.schema_version -eq 1) 'unexpected bootstrap state schema'
  Require ($state.phase -in @('bootstrap', 'windows_update', 'signing_tools', 'driver_gate', 'sysprep', 'sysprep_requested', 'terminal_success')) 'unexpected bootstrap phase'
  return $state
}}

function Save-State([object]$State) {{ Write-JsonAtomically $StatePath $State }}

function Fail-Closed([object]$State, [string]$Message) {{
  $State.phase = 'failed'; $State.failure = $Message; Save-State $State; throw $Message
}}

function Ensure-BootstrapTask() {{
  $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($null -ne $existing) {{
    $xml = Export-ScheduledTask -TaskName $TaskName
    Require ($xml -match '<UserId>S-1-5-18</UserId>') 'bootstrap task is not owned by LocalSystem'
    # schtasks /RU SYSTEM on Server Core persists LocalSystem as its SID and
    # omits LogonType entirely.  New-ScheduledTaskPrincipal instead writes the
    # unsafe InteractiveToken value, which must remain rejected.
    Require ($xml -notmatch '<LogonType>InteractiveToken</LogonType>') 'bootstrap task is interactive instead of LocalSystem'
    return $true
  }}
  Require (Test-Path -LiteralPath $BootstrapPath -PathType Leaf) 'bootstrap script is not staged at its pinned path'
  # Server Core 2025 serializes New-ScheduledTaskPrincipal for LocalSystem as
  # InteractiveToken despite -LogonType ServiceAccount.  schtasks /RU SYSTEM
  # writes the LocalSystem SID and deliberately omits LogonType.
  $powershell = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
  $taskCommand = '"' + $powershell + '" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $BootstrapPath + '"'
  & "$env:WINDIR\System32\schtasks.exe" /Create /TN $TaskName /SC ONSTART /RU SYSTEM /RL HIGHEST /TR $taskCommand /F | Out-Null
  Require ($LASTEXITCODE -eq 0) 'failed to create LocalSystem bootstrap task'
  $xml = Export-ScheduledTask -TaskName $TaskName
  Require ($xml -match '<UserId>S-1-5-18</UserId>') 'created bootstrap task is not owned by LocalSystem'
  Require ($xml -notmatch '<LogonType>InteractiveToken</LogonType>') 'created bootstrap task is interactive instead of LocalSystem'
  Start-ScheduledTask -TaskName $TaskName
  return $false
}}

function Restart-For-Resume([object]$State, [string]$NextPhase) {{
  $State.phase = $NextPhase; $State.reboot_count = [int]$State.reboot_count + 1
  Require ($State.reboot_count -le $MaximumReboots) 'bootstrap reboot limit reached'
  Save-State $State; Restart-Computer -Force; throw 'restart was requested but did not begin'
}}

function Get-MicrosoftSignatureEvidence([string]$Path) {{
  Require (Test-Path -LiteralPath $Path -PathType Leaf) "required signed file is missing: $Path"
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  Require ($signature.Status -eq 'Valid') "Authenticode signature is not valid: $Path"
  $subject = [string]$signature.SignerCertificate.Subject
  Require ($subject -match '(^|,)CN=Microsoft Corporation(,|$)') "signed file is not published by Microsoft Corporation: $Path"
  return [ordered]@{{
    path = $Path
    sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    signer_subject = $subject
    signer_issuer = [string]$signature.SignerCertificate.Issuer
    signer_thumbprint = [string]$signature.SignerCertificate.Thumbprint
    timestamp_subject = if ($null -eq $signature.TimeStamperCertificate) {{ $null }} else {{ [string]$signature.TimeStamperCertificate.Subject }}
  }}
}}

function Get-CloudbaseEvidence([string]$Path) {{
  Require (Test-Path -LiteralPath $Path -PathType Leaf) 'staged Cloudbase-Init MSI is missing'
  $actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
  Require ($actualSha256 -eq $CloudbaseExpectedSha256) 'staged Cloudbase-Init MSI SHA-256 does not match the M15-03 lock'
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  Require ($signature.Status -eq 'Valid') 'staged Cloudbase-Init MSI Authenticode signature is not valid'
  $actualPublisher = [string]$signature.SignerCertificate.Subject
  Require ($actualPublisher.Replace(' ', '') -eq $CloudbaseExpectedPublisher.Replace(' ', '')) 'staged Cloudbase-Init MSI publisher does not match the M15-03 lock'
  return [ordered]@{{ path = $Path; sha256 = $actualSha256; publisher = $actualPublisher }}
}}

function Find-VerifiedVirtioMediaDrive() {{
  # VirtIO is an untrusted read-only CD until the later signtool /kp gate.
  # A drive letter is assigned by Windows Setup and must never be assumed.
  $candidates = @(Get-Volume -ErrorAction Stop | Where-Object {{
    $null -ne $_.DriveLetter -and $_.FileSystemLabel -ceq $VirtioVolumeLabel
  }})
  Require ($candidates.Count -eq 1) ('expected exactly one mounted VirtIO volume labelled ' + $VirtioVolumeLabel)
  $drive = ([string]$candidates[0].DriveLetter) + ':'
  foreach ($relative in @('vioscsi\\2k25\\amd64\\vioscsi.inf', 'NetKVM\\2k25\\amd64\\netkvm.inf')) {{
    Require (Test-Path -LiteralPath (Join-Path ($drive + '\\') $relative) -PathType Leaf) ('expected VirtIO Server 2025 path is absent: ' + $relative)
  }}
  return $drive
}}

function Find-ValidMicrosoftSignTool() {{
  $root = Join-Path ${{env:ProgramFiles(x86)}} 'Windows Kits\10\bin'
  if (-not (Test-Path -LiteralPath $root -PathType Container)) {{ return $null }}
  $candidates = @(Get-ChildItem -LiteralPath $root -Filter signtool.exe -Recurse -File -ErrorAction Stop |
    Where-Object {{ $_.FullName -match '\\x64\\signtool\.exe$' }} | Sort-Object FullName -Descending)
  foreach ($candidate in $candidates) {{ try {{ return (Get-MicrosoftSignatureEvidence $candidate.FullName) }} catch {{ continue }} }}
  return $null
}}

function Install-SigningTools([object]$State) {{
  $existing = Find-ValidMicrosoftSignTool
  if ($null -ne $existing) {{
    $State.evidence.signing_tools = [ordered]@{{ source = 'preexisting_signed_windows_sdk'; signtool = $existing }}
    $State.phase = 'driver_gate'; Save-State $State; return
  }}
  if (Test-Path -LiteralPath $SdkInstallerPath) {{ Remove-Item -LiteralPath $SdkInstallerPath -Force -ErrorAction Stop }}
  Invoke-WebRequest -Uri $SdkInstallerUrl -OutFile $SdkInstallerPath -UseBasicParsing
  $setup = Get-MicrosoftSignatureEvidence $SdkInstallerPath
  $State.evidence.windows_sdk_setup = [ordered]@{{ source_url = $SdkInstallerUrl; setup = $setup }}; Save-State $State
  $process = Start-Process -FilePath $SdkInstallerPath -ArgumentList @('/features', 'OptionId.SigningTools', '/quiet', '/norestart') -Wait -PassThru
  if ($process.ExitCode -eq 3010) {{ Restart-For-Resume $State 'driver_gate' }}
  Require ($process.ExitCode -eq 0) ('Windows SDK SigningTools installer failed with exit code ' + $process.ExitCode)
  $installed = Find-ValidMicrosoftSignTool
  Require ($null -ne $installed) 'Windows SDK completed without a valid Microsoft x64 signtool.exe'
  $State.evidence.signing_tools = [ordered]@{{ source = 'newly_installed_windows_sdk'; signtool = $installed }}
  $State.phase = 'driver_gate'; Save-State $State
}}

function Install-CloudbaseAndOpenSsh([object]$State) {{
  $cloudbase = Join-Path 'C:\GoodBear\input-cache' $CloudbaseFileName
  $State.evidence.cloudbase_init = Get-CloudbaseEvidence $cloudbase; Save-State $State
  $process = Start-Process -FilePath "$env:WINDIR\System32\msiexec.exe" -ArgumentList @('/i', $cloudbase, '/qn', '/norestart') -Wait -PassThru
  if ($process.ExitCode -eq 3010) {{ Restart-For-Resume $State 'windows_update' }}
  Require ($process.ExitCode -eq 0) ('Cloudbase-Init installation failed with exit code ' + $process.ExitCode)
  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
  $sshCapability = Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
  Require ($sshCapability.State -eq 'Installed') 'OpenSSH Server capability did not install'
  Set-Service -Name sshd -StartupType Automatic; Start-Service -Name sshd
  $sshService = Get-Service -Name sshd -ErrorAction Stop
  $sshStartMode = (Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop).StartMode
  Require ($sshService.Status -eq 'Running' -and $sshStartMode -eq 'Auto') 'OpenSSH Server is not running with automatic start'
  $sshFirewall = Get-NetFirewallRule -Name 'GoodBear-M15-03-OpenSSH' -ErrorAction SilentlyContinue
  if ($null -eq $sshFirewall) {{
    $sshFirewall = New-NetFirewallRule -Name 'GoodBear-M15-03-OpenSSH' -DisplayName 'Good Bear M15-03 OpenSSH' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -Profile Any
  }}
  Require ($sshFirewall.Enabled -eq 'True' -and $sshFirewall.Direction -eq 'Inbound' -and $sshFirewall.Action -eq 'Allow') 'OpenSSH firewall rule is not enabled'
  $State.evidence.openssh = [ordered]@{{ capability = [string]$sshCapability.State; service_status = [string]$sshService.Status; start_mode = [string]$sshStartMode; firewall_rule = [string]$sshFirewall.Name }}
  $State.phase = 'windows_update'; Save-State $State
}}

function Start-WindowsUpdateWatchdog([object]$State, [int]$Pass) {{
  # The Windows Update COM calls below are synchronous and can wait
  # indefinitely on a broken servicing stack.  Do not turn that into a
  # silently stale Cloud image: persist the unfinished attempt, then use a
  # child SYSTEM job to restart only this resumable phase after a bounded
  # interval.  A subsequent boot records the recovery before retrying.
  $previous = $State.evidence.windows_update_attempt
  $recoveries = 0
  if ($null -ne $previous -and $previous.status -eq 'in_progress') {{
    $recoveries = [int]$previous.timeout_recoveries + 1
    Require ($recoveries -le $MaximumWindowsUpdateTimeoutRecoveries) 'Windows Update exceeded the bounded recovery limit'
    $State.evidence.windows_update_attempt = [ordered]@{{
      status = 'recovered_after_unfinished_attempt'
      previous_attempt_id = [string]$previous.attempt_id
      timeout_recoveries = $recoveries
      recovered_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    }}
    Save-State $State
  }}
  $attemptId = [guid]::NewGuid().ToString('N')
  $State.evidence.windows_update_attempt = [ordered]@{{
    status = 'in_progress'
    attempt_id = $attemptId
    pass = $Pass
    timeout_recoveries = $recoveries
    timeout_seconds = $WindowsUpdateOperationTimeoutSeconds
    started_at_utc = (Get-Date).ToUniversalTime().ToString('o')
  }}
  Save-State $State
  return Start-Job -ScriptBlock {{
    param([int]$TimeoutSeconds)
    Start-Sleep -Seconds $TimeoutSeconds
    Restart-Computer -Force
  }} -ArgumentList $WindowsUpdateOperationTimeoutSeconds
}}

function Stop-WindowsUpdateWatchdog([object]$Watchdog) {{
  if ($null -eq $Watchdog) {{ return }}
  try {{ Stop-Job -Job $Watchdog -ErrorAction SilentlyContinue | Out-Null }} finally {{
    Remove-Job -Job $Watchdog -Force -ErrorAction SilentlyContinue | Out-Null
  }}
}}

function Apply-WindowsUpdates([object]$State) {{
  for ($pass = [int]$State.update_passes + 1; $pass -le $MaximumUpdatePasses; $pass++) {{
    $watchdog = $null
    try {{
      $watchdog = Start-WindowsUpdateWatchdog $State $pass
      $session = New-Object -ComObject Microsoft.Update.Session
      $search = $session.CreateUpdateSearcher().Search('IsInstalled=0 and Type="Software"')
      if ($search.Updates.Count -eq 0) {{
        $State.evidence.windows_update_attempt.status = 'completed'
        $State.evidence.windows_update_attempt.completed_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        $State.update_passes = $pass - 1; $State.phase = 'signing_tools'; Save-State $State; return
      }}
      $collection = New-Object -ComObject Microsoft.Update.UpdateColl
      foreach ($update in $search.Updates) {{ [void]$collection.Add($update) }}
      $downloader = $session.CreateUpdateDownloader(); $downloader.Updates = $collection
      $download = $downloader.Download(); Require ($download.ResultCode -eq 2) 'Windows Update download did not succeed'
      $installer = $session.CreateUpdateInstaller(); $installer.Updates = $collection
      if ($installer.RebootRequiredBeforeInstallation) {{ $State.update_passes = $pass - 1; Restart-For-Resume $State 'windows_update' }}
      $result = $installer.Install(); Require ($result.ResultCode -eq 2) 'Windows Update installation did not succeed'
      $State.evidence.windows_update_attempt.status = 'completed'
      $State.evidence.windows_update_attempt.completed_at_utc = (Get-Date).ToUniversalTime().ToString('o')
      $State.update_passes = $pass; Save-State $State
      if ($result.RebootRequired) {{ Restart-For-Resume $State 'windows_update' }}
    }} finally {{ Stop-WindowsUpdateWatchdog $watchdog }}
  }}
  throw 'Windows Update pass limit reached before an empty update scan'
}}

function Inject-VerifiedVirtioDrivers([object]$State, [string]$MediaDrive) {{
  $dism = "$env:WINDIR\System32\dism.exe"; $records = @()
  foreach ($item in @(@('vioscsi', 'vioscsi.inf'), @('NetKVM', 'netkvm.inf'))) {{
    $inf = Join-Path ($MediaDrive + '\') ($item[0] + '\2k25\amd64\' + $item[1])
    Require (Test-Path -LiteralPath $inf -PathType Leaf) "verified VirtIO INF is missing: $inf"
    & $dism /Online /Add-Driver (('/Driver:' + $inf)) /NoRestart | Out-Null
    Require ($LASTEXITCODE -eq 0) "DISM refused verified VirtIO driver: $inf"
    $records += [ordered]@{{ path = $inf; sha256 = (Get-FileHash -LiteralPath $inf -Algorithm SHA256).Hash.ToLowerInvariant(); result = 'passed_dism_add_driver' }}
  }}
  $State.evidence.dism_driver_injection = $records; Save-State $State
}}

function Run-DriverGateAndPrepareSysprep([object]$State) {{
  Require (Test-Path -LiteralPath $GatePath -PathType Leaf) 'VirtIO signature gate is not staged at its pinned path'
  $signTool = Find-ValidMicrosoftSignTool; Require ($null -ne $signTool) 'valid Microsoft x64 signtool.exe is required before Sysprep'
  $mediaDrive = Find-VerifiedVirtioMediaDrive
  New-Item -ItemType Directory -Path $EvidenceDirectory -Force -ErrorAction Stop | Out-Null
  & $GatePath -MediaDrive $mediaDrive -EvidenceDirectory $EvidenceDirectory -SignTool $signTool.path
  Require ($LASTEXITCODE -eq 0) 'VirtIO signature gate failed'
  Inject-VerifiedVirtioDrivers $State $mediaDrive
  $State.phase = 'sysprep'; Save-State $State
}}

function Rotate-RecoveryCredentialBeforeSysprep([object]$State) {{
  # The one-shot host-local LogonUI recovery creates a random credential only
  # in its own process memory.  Before this disk can become a Cloud image,
  # overwrite the built-in Administrator verifier with a different random
  # value.  Do not use net.exe: command-line arguments are observable.  This
  # PowerShell API receives a SecureString and no value enters state/evidence.
  $accounts = @(Get-LocalUser -ErrorAction Stop | Where-Object {{ $_.SID.Value -match '-500$' }})
  Require ($accounts.Count -eq 1) 'expected exactly one built-in Administrator account by RID 500'
  $groups = @(
    [byte[]][char[]]'ABCDEFGHJKLMNPQRSTUVWXYZ',
    [byte[]][char[]]'abcdefghijkmnopqrstuvwxyz',
    [byte[]][char[]]'23456789',
    [byte[]][char[]]'!@#$%^&*-_'
  )
  $alphabet = [System.Collections.Generic.List[byte]]::new()
  foreach ($group in $groups) {{ $alphabet.AddRange($group) }}
  $random = [byte[]]::new(48)
  $characters = [char[]]::new(48)
  $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $plain = $null; $secure = $null
  try {{
    $generator.GetBytes($random)
    for ($index = 0; $index -lt $groups.Count; $index++) {{
      $characters[$index] = [char]$groups[$index][$random[$index] % $groups[$index].Length]
    }}
    for ($index = $groups.Count; $index -lt $characters.Length; $index++) {{
      $characters[$index] = [char]$alphabet[$random[$index] % $alphabet.Count]
    }}
    for ($index = $characters.Length - 1; $index -gt 0; $index--) {{
      $other = $random[$index % $random.Length] % ($index + 1)
      $swap = $characters[$index]; $characters[$index] = $characters[$other]; $characters[$other] = $swap
    }}
    $plain = [string]::new($characters)
    $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
    Set-LocalUser -InputObject $accounts[0] -Password $secure -ErrorAction Stop
  }} finally {{
    $secure = $null; $plain = $null
    [Array]::Clear($random, 0, $random.Length)
    [Array]::Clear($characters, 0, $characters.Length)
    $generator.Dispose()
  }}
  $State.evidence.recovery_credential_rotation = [ordered]@{{
    result = 'built_in_administrator_verifier_overwritten_before_sysprep'
    credential_value_recorded = $false
    command_line_secret_used = $false
  }}
  Save-State $State
}}

function Invoke-FinalSysprep([object]$State) {{
  Require ($State.phase -eq 'sysprep') 'Sysprep bypass blocked'
  Require (Test-Path -LiteralPath (Join-Path $EvidenceDirectory 'virtio-signature-gate.json') -PathType Leaf) 'VirtIO signature evidence is absent'
  # Policy TODO: do NOT auto-uninstall Windows SDK here. Firefox build tooling
  # may require it; removal needs a separately approved dependency decision.
  # Record intent before a shutdown can end this task.  If Windows shuts down
  # before Sysprep returns, the retained task later refuses a second Sysprep.
  Rotate-RecoveryCredentialBeforeSysprep $State
  $State.phase = 'sysprep_requested'; Save-State $State
  $process = Start-Process -FilePath "$env:WINDIR\System32\Sysprep\Sysprep.exe" -ArgumentList @('/oobe', '/generalize', '/shutdown') -Wait -PassThru
  Require ($process.ExitCode -eq 0) 'Sysprep failed'
  # Task removal is permitted only after the process returned success and the
  # terminal state was atomically persisted.  Otherwise it remains fail-closed.
  $State.phase = 'terminal_success'; Save-State $State
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
  Stop-Computer -Force
}}

if (-not (Ensure-BootstrapTask)) {{ return }}
$state = Read-State
try {{
  # A phase transition without a reboot must immediately advance to the next
  # phase.  Only Restart-For-Resume ends this task; its ONSTART trigger resumes
  # after Windows is back.  This makes the bootstrap fully headless.
  while ($true) {{
    switch ($state.phase) {{
      'bootstrap' {{ Install-CloudbaseAndOpenSsh $state }}
      'windows_update' {{ Apply-WindowsUpdates $state }}
      'signing_tools' {{ Install-SigningTools $state }}
      'driver_gate' {{ Run-DriverGateAndPrepareSysprep $state }}
      'sysprep' {{ Invoke-FinalSysprep $state; break }}
      'sysprep_requested' {{ Fail-Closed $state 'Sysprep was previously requested; refusing a second invocation' }}
      'terminal_success' {{ Fail-Closed $state 'terminal success state must not retain a scheduled task' }}
      default {{ Fail-Closed $state ('unreachable bootstrap phase: ' + $state.phase) }}
    }}
    $state = Read-State
  }}
}} catch {{ Fail-Closed $state $_.Exception.Message }}
'''
