#!/usr/bin/env python3
"""Native Windows primitives for a reboot-recovered, whole-VM offline worker.

Job Objects contain ordinary CreateProcess descendants, not every possible
delegated service operation. Consequently the coordinator never restores
networking in the boot that ran a worker. A fresh boot is the recovery barrier.
No operation in this module is a substitute for a real Windows boundary test.
"""

from __future__ import annotations

import ctypes
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


class NativeError(RuntimeError):
    pass


TRUSTED_PYTHON_BOOTSTRAP = (
    "import pathlib,runpy,sys;"
    "entry=sys.argv.pop(1);"
    "sys.path.insert(0,str(pathlib.Path(entry).parent));"
    "sys.argv[0]=entry;"
    "runpy.run_path(entry,run_name='__main__')"
)


def worker_owner(identifier: str) -> str:
    """Return the exact, net.exe-compatible ownership marker for a worker.

    ``net user /comment`` is deliberately used on Server Core, where the
    LocalAccounts module may be absent.  Its comment field is limited to 48
    characters, so retain the exact 32-hex job binding with a compact marker.
    """
    if not re.fullmatch(r"[0-9a-f]{32}", identifier):
        raise NativeError("invalid worker ownership identifier")
    return "GBN:" + identifier


LOCAL_USER_LOOKUP = r"""
# NetUserGetInfo is a native, local SAM query.  Unlike Win32_UserAccount it
# does not initialise the WMI provider, which can block indefinitely on the
# minimal Server Core image.  Level 1 supplies the account comment and flags;
# SID translation uses the Windows security authority for the same local name.
if (-not ("GoodBearLocalUserNative" -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class GoodBearLocalUserNative {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct UserInfo1 {
    public string Name; public string Password; public int PasswordAge;
    public int Privilege; public string HomeDirectory; public string Comment;
    public int Flags; public string ScriptPath;
  }
  [DllImport("Netapi32.dll", CharSet=CharSet.Unicode)]
  public static extern int NetUserGetInfo(string servername, string username,
    int level, out IntPtr buffer);
  [DllImport("Netapi32.dll")]
  public static extern int NetApiBufferFree(IntPtr buffer);
}
'@
}
function Get-GoodBearLocalUser([string]$Name) {
  [IntPtr]$buffer=[IntPtr]::Zero
  $status=[GoodBearLocalUserNative]::NetUserGetInfo($env:COMPUTERNAME,$Name,1,[ref]$buffer)
  if ($status -eq 2221) { return $null } # NERR_UserNotFound
  if ($status -ne 0) { throw 'native local user lookup failed' }
  try {
    $info=[Runtime.InteropServices.Marshal]::PtrToStructure($buffer,[type][GoodBearLocalUserNative+UserInfo1])
    $account=New-Object Security.Principal.NTAccount($env:COMPUTERNAME,$Name)
    $sid=$account.Translate([Security.Principal.SecurityIdentifier]).Value
    [pscustomobject]@{name=$info.Name; comment=$info.Comment; sid=$sid; enabled=(($info.Flags -band 2) -eq 0)}
  } finally {
    if ($buffer -ne [IntPtr]::Zero) {[void][GoodBearLocalUserNative]::NetApiBufferFree($buffer)}
  }
}
"""


def trusted_python_command(python: str, entry: Path, arguments: list[str], cache_parent: Path) -> list[str]:
    """Start a verified wrapper without environment, site, or old bytecode hooks.

    Callers verify the complete source import tree before invoking this command.
    Scheduled roles use separate cache directories below the protected job stage;
    -B keeps those directories empty when a recovery task is retried after reboot.
    Mach/virtualenv entry points deliberately do not use this wrapper.
    """
    cache_parent.mkdir(parents=True, exist_ok=True)
    if cache_parent.is_symlink() or getattr(cache_parent, "is_junction", lambda: False)():
        raise NativeError("trusted Python cache parent cannot be a reparse point")
    cache = Path(tempfile.mkdtemp(prefix="python-startup-", dir=cache_parent))
    return [str(python), "-I", "-S", "-B", "-u", "-X", f"pycache_prefix={cache}",
            "-c", TRUSTED_PYTHON_BOOTSTRAP, str(entry), *arguments]


def require_native() -> None:
    if sys.platform != "win32":
        raise NativeError("whole-VM operations require native Windows")


def powershell(script: str, values: dict | None = None, *, timeout: int = 120,
               safe_label: str = "native administration") -> object:
    require_native()
    prefix = "$ErrorActionPreference='Stop'; $p=[Console]::In.ReadToEnd() | ConvertFrom-Json; "
    process = subprocess.Popen(
        [str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"),
         "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prefix + script],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    payload = json.dumps(values or {})
    started = time.monotonic()
    while True:
        try:
            stdout, _private_stderr = process.communicate(input=payload, timeout=15)
            break
        except subprocess.TimeoutExpired:
            payload = None
            elapsed = int(time.monotonic() - started)
            print(f"native administration process active: {elapsed}s", flush=True)
            if elapsed >= timeout:
                process.kill()
                process.communicate()
                raise NativeError("native administration timed out; cleanup is unproven")
    if process.returncode:
        # Payloads may contain the newly generated account password. Do not
        # reflect a PowerShell exception or command body into evidence/logs.
        raise NativeError(
            f"native administration command failed ({process.returncode}) during {safe_label}; private details suppressed"
        )
    output = stdout.strip()
    return json.loads(output) if output else None


INVENTORY_SCRIPT = r"""
$os = Get-CimInstance Win32_OperatingSystem
$adapters = @(Get-NetAdapter -IncludeHidden | ForEach-Object {
  @{guid=$_.InterfaceGuid.ToString(); index=[int]$_.ifIndex;
    enabled=($_.AdminStatus -eq 'Up'); status=$_.Status.ToString()}
})
$loopback = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
  Where-Object {$_.NetworkInterfaceType -eq 'Loopback'} | ForEach-Object {
    $properties=$_.GetIPProperties()
    if ($_.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv4)) {
      $properties.GetIPv4Properties().Index
    }
    if ($_.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv6)) {
      $properties.GetIPv6Properties().Index
    }
  } | Select-Object -Unique)
$connected = @(Get-NetIPInterface | Where-Object {
  $_.ConnectionState -eq 'Connected' -and $_.InterfaceIndex -notin $loopback
} | ForEach-Object {[int]$_.InterfaceIndex})
$routes = @(Get-NetRoute -PolicyStore ActiveStore | ForEach-Object {
  @{index=[int]$_.InterfaceIndex; prefix=$_.DestinationPrefix; next_hop=$_.NextHop}
})
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
  @{name=$_.Name; enabled=[bool]$_.Enabled}
})
$cpu = (Get-CimInstance Win32_ComputerSystem)
$machine = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
$uuid = (Get-CimInstance Win32_ComputerSystemProduct).UUID
$ubr = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
foreach ($identifier in @($machine, $uuid)) {
  if ($identifier -notmatch '^[0-9a-fA-F-]{36}$' -or
      $identifier.Replace('-', '') -match '^(0+|[fF]+)$') {throw 'stable VM identity is unavailable'}
}
$identityBytes = [Text.Encoding]::UTF8.GetBytes(($machine.ToLowerInvariant()+'|'+$uuid.ToLowerInvariant()+'|'+$os.Version+'|'+$os.BuildNumber+'|'+$ubr))
$identityHash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($identityBytes)).Replace('-', '').ToLowerInvariant()
@{boot=$os.LastBootUpTime.ToUniversalTime().ToString('o');
  vm_identity_sha256=$identityHash;
  adapters=$adapters; loopback=$loopback; connected=$connected; routes=$routes;
  firewall_profiles=$profiles; cpus=[int]$cpu.NumberOfLogicalProcessors;
  memory_bytes=[long]$cpu.TotalPhysicalMemory;
  system=([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18')
} | ConvertTo-Json -Depth 6 -Compress
"""


class WindowsBackend:
    @contextmanager
    def arm_lock(self):
        require_native()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        kernel.CreateMutexW.restype = HANDLE
        kernel.WaitForSingleObject.argtypes = [HANDLE, DWORD]
        kernel.WaitForSingleObject.restype = DWORD
        kernel.ReleaseMutex.argtypes = [HANDLE]
        kernel.CloseHandle.argtypes = [HANDLE]
        handle = kernel.CreateMutexW(None, False, "Global\\GoodBear-Offline-Arming")
        acquired = False
        try:
            if not handle or kernel.WaitForSingleObject(handle, 0) not in {0, 0x80}:
                raise NativeError("another native job arm operation is active")
            acquired = True
            yield
        finally:
            if acquired:
                kernel.ReleaseMutex(handle)
            if handle:
                kernel.CloseHandle(handle)

    def inventory(self) -> dict:
        return powershell(INVENTORY_SCRIPT)

    def protect_job(self, directory: Path) -> None:
        powershell(r"""
& icacls.exe $p.path /setowner '*S-1-5-32-544' /Q | Out-Null
if ($LASTEXITCODE -ne 0) {throw 'job owner failed'}
& icacls.exe $p.path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
if ($LASTEXITCODE -ne 0) {throw 'job ACL failed'}
""", {"path": str(directory)})

    def verify_private_acl(self, path: Path, purpose: str, worker_sid: str | None = None,
                           trusted_root: Path | None = None) -> bool:
        """Validate trusted ownership, effective allow entries and replacement paths.

        Never repair an existing receipt/key ACL and then trust its old bytes.
        The exact ephemeral worker may read inputs, but cannot modify them.
        """
        result = powershell(r"""
$reason=$null
try {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $principal=New-Object Security.Principal.WindowsPrincipal($identity)
  $trusted=@('S-1-5-18','S-1-5-32-544')
  if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {$trusted += $identity.User.Value}
  $item=Get-Item -LiteralPath $p.path -Force -ErrorAction Stop
  $stop=$null
  if ($p.trusted_root) {
    $stop=[IO.Path]::GetFullPath($p.trusted_root).TrimEnd('\')
    $target=[IO.Path]::GetFullPath($item.FullName).TrimEnd('\')
    if (-not ($target.Equals($stop,[StringComparison]::OrdinalIgnoreCase) -or $target.StartsWith($stop+'\',[StringComparison]::OrdinalIgnoreCase))) {
      throw 'private path escapes trusted root'
    }
  }
  $first=$true
  while ($item) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'private path is a reparse point'}
    $acl=Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $trusted) {throw 'private path has an untrusted owner'}
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
      if ($rule.AccessControlType -ne 'Allow' -or ($rule.PropagationFlags -band 2)) {continue}
      $sid=$rule.IdentityReference.Value
      if ($sid -in $trusted) {continue}
      $rights=[long]$rule.FileSystemRights
      if ($first) {
        if (-not $p.worker_sid -or $sid -ne $p.worker_sid -or ($rights -band 0xD0156)) {throw 'private input grants untrusted access'}
      } elseif ($rights -band 0xD0040) {throw 'ancestor permits untrusted replacement'}
    }
    $first=$false
    if ($stop -and $item.FullName.TrimEnd('\').Equals($stop,[StringComparison]::OrdinalIgnoreCase)) {break}
    if ($item -is [IO.DirectoryInfo]) {$item=$item.Parent} else {$item=$item.Directory}
  }
  @{ok=$true;reason=$null} | ConvertTo-Json -Compress
} catch {
  $message=$_.Exception.Message
  if ($message -eq 'private path escapes trusted root') {$reason='trusted-root-escape'}
  elseif ($message -eq 'private path is a reparse point') {$reason='reparse-point'}
  elseif ($message -eq 'private path has an untrusted owner') {$reason='untrusted-owner'}
  elseif ($message -eq 'private input grants untrusted access') {$reason='untrusted-target-access'}
  elseif ($message -eq 'ancestor permits untrusted replacement') {$reason='untrusted-ancestor-replacement'}
  else {$reason='native-acl-command'}
  @{ok=$false;reason=$reason} | ConvertTo-Json -Compress
}
""", {"path": str(path), "purpose": purpose, "worker_sid": worker_sid,
       "trusted_root": str(trusted_root) if trusted_root is not None else None},
       safe_label=f"{purpose} ACL validation")
        if not isinstance(result, dict) or result.get("ok") is not True:
            reason = result.get("reason") if isinstance(result, dict) else "malformed-result"
            raise NativeError(f"{purpose} ACL validation failed: {reason}")
        return True

    def seal_new_job(self, directory: Path) -> None:
        # Only called on a freshly prepared, never-launched stage. File owners
        # must remain verifiable when SYSTEM later consumes administrator-made
        # descriptors/inputs; directory ownership itself does not inherit.
        powershell(r"""
& icacls.exe $p.path /setowner '*S-1-5-32-544' /T /Q | Out-Null
if ($LASTEXITCODE -ne 0) {throw 'new job ownership sealing failed'}
""", {"path": str(directory)})

    def current_user_sid(self) -> str:
        return powershell("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value | ConvertTo-Json -Compress")

    def grant_private_inputs(self, directory: Path, sid: str) -> None:
        powershell(r"""
& icacls.exe $p.path /grant:r ('*'+$p.sid+':(OI)(CI)RX') /T /Q | Out-Null
if ($LASTEXITCODE -ne 0) {throw 'private input read ACL failed'}
""", {"path": str(directory), "sid": sid})

    def register_tasks(self, job: dict, job_path: Path, digest: str) -> None:
        arguments = ["--job", str(job_path), "--job-sha256", digest]
        worker = trusted_python_command(job["python"], Path(job["executor"]),
                                        [*arguments, "_worker"], job_path.parent)
        recovery = trusted_python_command(job["python"], Path(job["executor"]),
                                          [*arguments, "_recover"], job_path.parent)
        values = {"python": job["python"], "worker": job["worker_task"],
                  "watchdog": job["watchdog_task"], "deadline": job["deadline"],
                  "worker_args": subprocess.list2cmdline(worker[1:]),
                  "watchdog_args": subprocess.list2cmdline(recovery[1:]),
                  "limit_seconds": job["timeout_seconds"] + 300}
        powershell(r"""
if ((Get-ScheduledTask -TaskName $p.worker -ErrorAction SilentlyContinue) -or
    (Get-ScheduledTask -TaskName $p.watchdog -ErrorAction SilentlyContinue)) {throw 'task collision'}
$created=@()
try {
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$workerAction=New-ScheduledTaskAction -Execute $p.python -Argument $p.worker_args
$disabled=New-ScheduledTaskSettingsSet -Disable -ExecutionTimeLimit (New-TimeSpan -Seconds $p.limit_seconds)
Register-ScheduledTask -TaskName $p.worker -Action $workerAction -Principal $principal -Settings $disabled | Out-Null
$created += $p.worker
$recoveryAction=New-ScheduledTaskAction -Execute $p.python -Argument $p.watchdog_args
$triggers=@((New-ScheduledTaskTrigger -AtStartup),
  (New-ScheduledTaskTrigger -Once -At ([DateTimeOffset]::Parse($p.deadline).LocalDateTime)))
$settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $p.watchdog -Action $recoveryAction -Trigger $triggers -Principal $principal -Settings $settings | Out-Null
$created += $p.watchdog
if ((Get-ScheduledTask -TaskName $p.worker).State -ne 'Disabled') {throw 'worker is not disabled'}
if ((Get-ScheduledTask -TaskName $p.watchdog).Principal.UserId -notin @('SYSTEM','S-1-5-18')) {throw 'recovery principal mismatch'}
} catch {
  # Both registrations precede the explicit launch. Roll back only tasks
  # created by this invocation; never delete a colliding pre-existing task.
  foreach($name in $created) {Unregister-ScheduledTask -TaskName $name -Confirm:$false}
  throw
}
""", values)

    def launch(self, job: dict) -> None:
        powershell(r"""
Enable-ScheduledTask -TaskName $p.task | Out-Null
Start-ScheduledTask -TaskName $p.task
""", {"task": job["worker_task"]})

    def remove_tasks(self, job: dict) -> None:
        powershell(r"""
foreach($name in @($p.worker,$p.watchdog)) {
  if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false
  }
}
if (@(Get-ScheduledTask -ErrorAction Stop | Where-Object {$_.TaskName -in @($p.worker,$p.watchdog)}).Count) {throw 'owned task removal is unproven'}
""", {"worker": job["worker_task"], "watchdog": job["watchdog_task"]})

    def block_network(self, job: dict) -> None:
        powershell(r"""
if (Get-NetFirewallRule -Name $p.rule -ErrorAction SilentlyContinue) {throw 'firewall rule collision'}
New-NetFirewallRule -Name $p.rule -DisplayName $p.rule -Direction Outbound -Action Block -Profile Any -Protocol Any -Enabled True | Out-Null
Get-NetAdapter -IncludeHidden | Where-Object {$_.ifIndex -notin $p.loopback} |
  Disable-NetAdapter -Confirm:$false
""", {"rule": job["firewall_rule"], "loopback": job["original_network"]["loopback"]})

    def rule_active(self, job: dict) -> bool:
        return powershell(r"""
$r=Get-NetFirewallRule -PolicyStore ActiveStore -Name $p.rule -ErrorAction SilentlyContinue
[bool]($r -and $r.Enabled -eq 'True' -and $r.Direction -eq 'Outbound' -and $r.Action -eq 'Block' -and $r.Profile -eq 'Any') | ConvertTo-Json -Compress
""", {"rule": job["firewall_rule"]}) is True

    def owned_rule_absent(self, job: dict) -> bool:
        return powershell(r"""
$rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {$_.Name -eq $p.rule})
($rules.Count -eq 0) | ConvertTo-Json -Compress
""", {"rule": job["firewall_rule"]}) is True

    def verify_worker_io(self, job_object: str, username: str, password: str, sid: str,
                         command: list[str], cwd: Path, environment: dict[str, str]) -> bool:
        """Run a bounded, no-network file-I/O probe in the exact worker token."""
        probe = NativeJob(job_object)
        try:
            probe.allow_worker_query(sid)
            probe.start(username, password, command, cwd, environment)
            return probe.wait(time.monotonic() + 60, lambda: None) == 0
        finally:
            probe.close()

    def verify_provisioning_boundaries(self, root: Path, workspace: Path, stage: Path,
                                      descriptor: Path, worker_probe: Path, private_probe: Path,
                                      sid: str) -> bool:
        """Prove every ACL boundary used before a worker can enter offline mode.

        This is deliberately a read-only verifier.  The preflight caller has
        already exercised the exact mutation calls; this prevents a successful
        native command with an ineffective or inherited ACL from being trusted.
        """
        return powershell(r"""
$workerSid=[Security.Principal.SecurityIdentifier]$p.sid
$groupSid=(New-Object Security.Principal.NTAccount($env:COMPUTERNAME,'GoodBear-Offline-Workers')).Translate([Security.Principal.SecurityIdentifier])
$admins=[Security.Principal.SecurityIdentifier]'S-1-5-32-544'
$system=[Security.Principal.SecurityIdentifier]'S-1-5-18'
function Rules([string]$path) {
  @( (Get-Acl -LiteralPath $path -ErrorAction Stop).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) )
}
function HasRule([object[]]$rules, $identity, [Security.AccessControl.AccessControlType]$type, [long]$rights) {
  @($rules | Where-Object {$_.IdentityReference -eq $identity -and $_.AccessControlType -eq $type -and ((([long]$_.FileSystemRights) -band $rights) -eq $rights)}).Count -gt 0
}
$writeMask=[long]([Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership)
$full=[long][Security.AccessControl.FileSystemRights]::FullControl
$rx=[long][Security.AccessControl.FileSystemRights]::ReadAndExecute
$modify=[long][Security.AccessControl.FileSystemRights]::Modify
$read=[long][Security.AccessControl.FileSystemRights]::Read
$source=Rules $p.root
if (-not (HasRule $source $groupSid ([Security.AccessControl.AccessControlType]::Allow) $rx) -or -not (HasRule $source $groupSid ([Security.AccessControl.AccessControlType]::Deny) $writeMask)) {throw 'source group ACL boundary is ineffective'}
foreach($item in @(@{path=$p.workspace;rights=$modify;label='workspace'},@{path=$p.stage;rights=$rx;label='stage'})) {
  $rules=Rules $item.path
  if (-not (HasRule $rules $system ([Security.AccessControl.AccessControlType]::Allow) $full) -or -not (HasRule $rules $admins ([Security.AccessControl.AccessControlType]::Allow) $full) -or -not (HasRule $rules $workerSid ([Security.AccessControl.AccessControlType]::Allow) $item.rights)) {throw ($item.label+' ACL boundary is ineffective')}
  if (@($rules | Where-Object {$_.IdentityReference -eq $groupSid}).Count) {throw ($item.label+' retains the source worker-group ACL')}
}
if (-not (HasRule (Rules $p.descriptor) $workerSid ([Security.AccessControl.AccessControlType]::Allow) $read)) {throw 'descriptor ACL boundary is ineffective'}
if (-not (HasRule (Rules $p.worker_probe) $workerSid ([Security.AccessControl.AccessControlType]::Allow) $rx)) {throw 'worker probe ACL boundary is ineffective'}
if (-not (HasRule (Rules $p.private_probe) $workerSid ([Security.AccessControl.AccessControlType]::Allow) $read)) {throw 'private-input ACL boundary is ineffective'}
$true | ConvertTo-Json -Compress
""", {"root": str(root), "workspace": str(workspace), "stage": str(stage),
       "descriptor": str(descriptor), "worker_probe": str(worker_probe),
       "private_probe": str(private_probe), "sid": sid},
       safe_label="restricted worker ACL boundary verification") is True

    def provision_worker_workspace_acl(self, workspace: Path, sid: str) -> None:
        powershell(r"""
$groupSid=(New-Object Security.Principal.NTAccount($env:COMPUTERNAME,$p.group)).Translate([Security.Principal.SecurityIdentifier]).Value
& icacls.exe $p.workspace /inheritance:r /remove:g ('*'+$groupSid) /remove:d ('*'+$groupSid) /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' ('*'+$p.sid+':(OI)(CI)M') /Q | Out-Null
if ($LASTEXITCODE -ne 0) {throw 'workspace ACL isolation failed'}
""", {"workspace": str(workspace), "sid": sid, "group": "GoodBear-Offline-Workers"}, timeout=600,
       safe_label="restricted worker workspace ACL isolation")

    def provision_worker_stage_acl(self, stage: Path, sid: str) -> None:
        powershell(r"""
$groupSid=(New-Object Security.Principal.NTAccount($env:COMPUTERNAME,$p.group)).Translate([Security.Principal.SecurityIdentifier]).Value
& icacls.exe $p.stage /inheritance:r /remove:g ('*'+$groupSid) /remove:d ('*'+$groupSid) /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' ('*'+$p.sid+':RX') /Q | Out-Null
if ($LASTEXITCODE -ne 0) {throw 'job traversal ACL isolation failed'}
""", {"stage": str(stage), "sid": sid, "group": "GoodBear-Offline-Workers"},
       safe_label="restricted worker job traversal ACL isolation")

    def grant_worker_descriptor_read(self, stage: Path, sid: str) -> None:
        powershell(r"""
& icacls.exe (Join-Path $p.stage 'job.json') /grant:r ('*'+$p.sid+':(R)') /Q | Out-Null
if ($LASTEXITCODE -ne 0) {throw 'descriptor read ACL failed'}
""", {"stage": str(stage), "sid": sid},
       safe_label="restricted worker descriptor read ACL")

    def grant_worker_probe_read(self, worker_probe: Path, sid: str) -> None:
        """Grant the exact worker read/execute access to its bounded probe only."""
        powershell(r"""
& icacls.exe $p.probe /grant:r ('*'+$p.sid+':RX') /Q | Out-Null
if ($LASTEXITCODE -ne 0) {throw 'worker probe read ACL failed'}
""", {"probe": str(worker_probe), "sid": sid},
       safe_label="restricted worker probe read ACL")

    def create_account(self, name: str, password: str, root: Path, workspace: Path, stage: Path,
                       *, provision_workspace: bool = True, provision_stage: bool = True,
                       provision_descriptor: bool = True) -> str:
        # Server Core can omit LocalAccounts, and its Win32_UserAccount WMI
        # provider can block.  Use net.exe for mutation and NetUserGetInfo for
        # the comment/flags contract plus native SID translation.
        owner = worker_owner(stage.name)
        sid = powershell(LOCAL_USER_LOOKUP + r"""
$created=$false
try {
  # Server Core accepts the compatible short password only with bare /add.
  # Apply the ownership marker as a separate native operation.
  & net.exe user $p.name $p.password /add | Out-Null
  if ($LASTEXITCODE -ne 0) {throw 'worker account creation failed'}
  $created=$true
  & net.exe user $p.name ('/comment:'+$p.owner) | Out-Null
  if ($LASTEXITCODE -ne 0) {throw 'worker account ownership assignment failed'}
  $account=Get-GoodBearLocalUser $p.name
  if (-not $account -or $account.name -cne $p.name -or $account.comment -cne $p.owner -or -not $account.sid) {throw 'worker account identity is unproven'}
  & net.exe localgroup $p.group $p.name /add | Out-Null
  if ($LASTEXITCODE -ne 0) {throw 'worker isolation-group assignment failed'}
  $account.sid | ConvertTo-Json -Compress
} catch {
  if ($created) { & net.exe user $p.name /delete | Out-Null }
  throw
}
""", {"name": name, "password": password, "group": "GoodBear-Offline-Workers",
       "owner": owner},
       safe_label="restricted worker account creation")
        if provision_workspace:
            self.provision_worker_workspace_acl(workspace, sid)
        if provision_stage:
            self.provision_worker_stage_acl(stage, sid)
        if provision_descriptor:
            self.grant_worker_descriptor_read(stage, sid)
        return sid

    def disable_account(self, job: dict, sid: str | None) -> None:
        powershell(LOCAL_USER_LOOKUP + r"""
$user=Get-GoodBearLocalUser $p.name
if ($user) {
  if ($user.comment -cne $p.owner) {throw 'worker account ownership is unproven'}
  if ($p.sid -and $user.sid -ne $p.sid) {throw 'worker SID changed'}
  & net.exe user $p.name /active:no | Out-Null
  if ($LASTEXITCODE -ne 0) {throw 'worker account disable failed'}
  $after=Get-GoodBearLocalUser $p.name
  if (-not $after -or $after.enabled) {throw 'worker account remains enabled'}
}
""", {"name": job["worker_account"], "sid": sid, "owner": worker_owner(job["id"])})

    def enable_account(self, job: dict, sid: str) -> None:
        """Enable only the exact, already-provisioned offline worker."""
        powershell(LOCAL_USER_LOOKUP + r"""
$user=Get-GoodBearLocalUser $p.name
if (-not $user -or $user.comment -cne $p.owner -or $user.sid -ne $p.sid -or $user.enabled) {
  throw 'offline worker identity is not a disabled exact match'
}
& net.exe user $p.name /active:yes | Out-Null
if ($LASTEXITCODE -ne 0) {throw 'worker account enable failed'}
$after=Get-GoodBearLocalUser $p.name
if (-not $after -or -not $after.enabled -or $after.sid -ne $p.sid) {throw 'worker account enable is unproven'}
""", {"name": job["worker_account"], "sid": sid, "owner": worker_owner(job["id"])})

    def quiescent_after_boot(self, job: dict, sid: str | None) -> bool:
        return powershell(LOCAL_USER_LOOKUP + r"""
if (Get-ScheduledTask -TaskName $p.worker -ErrorAction SilentlyContinue) {
  Disable-ScheduledTask -TaskName $p.worker | Out-Null
  Stop-ScheduledTask -TaskName $p.worker
  if ((Get-ScheduledTask -TaskName $p.worker).State -ne 'Disabled') {throw 'worker task is not stopped and disabled'}
}
$user=Get-GoodBearLocalUser $p.name
if ($user -and $user.comment -cne $p.owner) {throw 'worker account ownership is unproven'}
if ($user -and $user.enabled) {throw 'worker account is enabled'}
if ($user -and $p.sid -and $user.sid -ne $p.sid) {throw 'worker SID changed'}
$active=@(Get-CimInstance Win32_Process | Where-Object {$_.ProcessId -notin @(0,4)} | ForEach-Object {
  $process=$_
  $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction Stop
  if ($owner.ReturnValue -ne 0) {
    if (Get-CimInstance Win32_Process -Filter ('ProcessId='+$process.ProcessId)) {
      throw 'cannot establish fresh-boot process owner'
    }
  } elseif ($owner.User -eq $p.name) {$process}
})
($active.Count -eq 0) | ConvertTo-Json -Compress
""", {"worker": job["worker_task"], "name": job["worker_account"], "sid": sid,
       "owner": worker_owner(job["id"])}) is True

    def remove_account(self, job: dict, sid: str | None, root: Path, stage: Path) -> None:
        powershell(LOCAL_USER_LOOKUP + r"""
$user=Get-GoodBearLocalUser $p.name
if ($user) {
  if ($user.comment -cne $p.owner) {throw 'worker account ownership is unproven'}
  if ($user.enabled) {throw 'cannot remove an enabled worker'}
  if ($p.sid -and $user.sid -ne $p.sid) {throw 'worker identity changed'}
  $sid=$user.sid
} else {$sid=$p.sid}
if ($sid) {
  & icacls.exe $p.stage /remove ('*'+$sid) /T /Q | Out-Null
  if ($LASTEXITCODE -ne 0) {throw 'worker descriptor ACL removal failed'}
}
if ($user) {
  & net.exe user $p.name /delete | Out-Null
  if ($LASTEXITCODE -ne 0) {throw 'worker account removal failed'}
  if (Get-GoodBearLocalUser $p.name) {throw 'worker account removal failed'}
}
""", {"name": job["worker_account"], "sid": sid, "stage": str(stage),
       "owner": worker_owner(job["id"])}, timeout=600)

    def restore_network(self, job: dict) -> None:
        powershell(r"""
$adapters=@(Get-NetAdapter -IncludeHidden)
foreach($before in $p.original.adapters) {
  $found=@($adapters | Where-Object {$_.InterfaceGuid.ToString() -eq $before.guid})
  if ($found.Count -ne 1) {throw 'adapter identity changed'}
  if ($before.enabled) {$found[0] | Enable-NetAdapter -Confirm:$false}
}
if (Get-NetFirewallRule -Name $p.rule -ErrorAction SilentlyContinue) {
  Remove-NetFirewallRule -Name $p.rule
}
""", {"original": job["original_network"], "rule": job["firewall_rule"]})

    def reboot(self) -> None:
        require_native()
        result = subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/shutdown.exe"),
                                 "/r", "/t", "5", "/d", "p:4:1", "/c",
                                 "Good Bear offline worker network recovery"], check=False, capture_output=True)
        if result.returncode:
            raise NativeError("reboot request failed; networking remains disabled")


DWORD = ctypes.c_uint32
HANDLE = ctypes.c_void_p
SIZE_T = ctypes.c_size_t


class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", DWORD), ("reserved", ctypes.c_wchar_p), ("desktop", ctypes.c_wchar_p),
                ("title", ctypes.c_wchar_p), ("x", DWORD), ("y", DWORD), ("xsize", DWORD),
                ("ysize", DWORD), ("xchars", DWORD), ("ychars", DWORD), ("fill", DWORD),
                ("flags", DWORD), ("show", ctypes.c_uint16), ("reserved2size", ctypes.c_uint16),
                ("reserved2", ctypes.c_void_p), ("stdin", HANDLE), ("stdout", HANDLE), ("stderr", HANDLE)]


class PROCESSINFO(ctypes.Structure):
    _fields_ = [("process", HANDLE), ("thread", HANDLE), ("pid", DWORD), ("tid", DWORD)]


class BASICLIMIT(ctypes.Structure):
    _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64), ("flags", DWORD),
                ("minimum", SIZE_T), ("maximum", SIZE_T), ("process_limit", DWORD),
                ("affinity", SIZE_T), ("priority", DWORD), ("scheduling", DWORD)]


class EXTENDEDLIMIT(ctypes.Structure):
    _fields_ = [("basic", BASICLIMIT), ("io", ctypes.c_uint64 * 6),
                ("process_memory", SIZE_T), ("job_memory", SIZE_T),
                ("peak_process_memory", SIZE_T), ("peak_job_memory", SIZE_T)]


class NativeJob:
    """Create a suspended unprivileged process before assigning its Job Object."""
    def __init__(self, name: str):
        require_native()
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        self.kernel.CreateJobObjectW.restype = HANDLE
        self.kernel.CloseHandle.argtypes = [HANDLE]
        self.kernel.SetInformationJobObject.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD]
        self.kernel.AssignProcessToJobObject.argtypes = [HANDLE, HANDLE]
        self.kernel.ResumeThread.argtypes = [HANDLE]
        self.kernel.ResumeThread.restype = DWORD
        self.kernel.WaitForSingleObject.argtypes = [HANDLE, DWORD]
        self.kernel.WaitForSingleObject.restype = DWORD
        self.kernel.GetExitCodeProcess.argtypes = [HANDLE, ctypes.POINTER(DWORD)]
        self.kernel.TerminateJobObject.argtypes = [HANDLE, ctypes.c_uint]
        self.kernel.TerminateProcess.argtypes = [HANDLE, ctypes.c_uint]
        self.advapi.LogonUserW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                         DWORD, DWORD, ctypes.POINTER(HANDLE)]
        self.advapi.GetTokenInformation.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                   DWORD, ctypes.POINTER(DWORD)]
        self.advapi.CreateProcessAsUserW.argtypes = [HANDLE, ctypes.c_wchar_p, ctypes.c_wchar_p,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, DWORD, ctypes.c_void_p,
            ctypes.c_wchar_p, ctypes.POINTER(STARTUPINFO), ctypes.POINTER(PROCESSINFO)]
        self.advapi.CreateProcessWithLogonW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p,
            ctypes.c_wchar_p, DWORD, ctypes.c_wchar_p, ctypes.c_wchar_p, DWORD,
            ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(STARTUPINFO),
            ctypes.POINTER(PROCESSINFO)]
        self.advapi.CreateProcessWithLogonW.restype = ctypes.c_int
        ctypes.set_last_error(0)
        self.handle = self.kernel.CreateJobObjectW(None, name)
        if not self.handle or ctypes.get_last_error() == 183:
            if self.handle:
                self.kernel.CloseHandle(self.handle)
            raise NativeError("cannot create a unique native Job Object")
        self.process = None
        limits = EXTENDEDLIMIT()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway.
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise NativeError("cannot enforce kill-on-close Job Object")

    def allow_worker_query(self, sid: str) -> None:
        if not re.fullmatch(r"S-\d+(?:-\d+)+", sid):
            raise NativeError("invalid native worker SID")
        self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            ctypes.c_wchar_p, DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(DWORD)]
        self.advapi.SetKernelObjectSecurity.argtypes = [HANDLE, DWORD, ctypes.c_void_p]
        self.kernel.LocalFree.argtypes = [ctypes.c_void_p]
        descriptor = ctypes.c_void_p()
        # The worker may query membership only; it cannot change job limits,
        # assign other processes, terminate the job or rewrite its DACL.
        sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000004;;;" + sid + ")"
        if not self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise NativeError("cannot construct native Job Object query ACL")
        try:
            if not self.advapi.SetKernelObjectSecurity(self.handle, 4, descriptor):
                raise NativeError("cannot grant exact worker Job Object query access")
        finally:
            self.kernel.LocalFree(descriptor)

    def start(self, username: str, password: str, command: list[str], cwd: Path,
              environment: dict[str, str]) -> None:
        token = HANDLE()
        if not self.advapi.LogonUserW(username, ".", password, 2, 0, ctypes.byref(token)):
            raise NativeError("cannot log on the newly created offline worker")
        info = PROCESSINFO()
        try:
            elevation, length = DWORD(), DWORD()
            if not self.advapi.GetTokenInformation(token, 20, ctypes.byref(elevation),
                                                   ctypes.sizeof(elevation), ctypes.byref(length)) or elevation.value:
                raise NativeError("build worker token must not be elevated")
            startup = STARTUPINFO()
            startup.cb = ctypes.sizeof(startup)
            block = ctypes.create_unicode_buffer("\0".join(k + "=" + v for k, v in sorted(environment.items())) + "\0\0")
            command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
            flags = 0x4 | 0x400 | 0x08000000  # suspended, Unicode environment, no window
            ctypes.set_last_error(0)
            created = self.advapi.CreateProcessAsUserW(token, command[0], command_line, None, None, False,
                                                        flags, block, str(cwd), ctypes.byref(startup), ctypes.byref(info))
            # GitHub's Windows service account on the Cloud.ru image does not
            # hold SeIncreaseQuota/SeAssignPrimaryToken.  Microsoft documents
            # CreateProcessWithLogonW as the no-special-privilege alternative
            # for exactly ERROR_PRIVILEGE_NOT_HELD (1314).  The same ephemeral
            # account/password were authenticated above and the process remains
            # suspended until it is assigned to this exact kill-on-close Job.
            if not created and ctypes.get_last_error() == 1314:
                ctypes.set_last_error(0)
                created = self.advapi.CreateProcessWithLogonW(username, ".", password, 0, command[0], command_line,
                                                               flags, block, str(cwd), ctypes.byref(startup), ctypes.byref(info))
            if not created:
                raise NativeError("cannot create suspended native worker")
            if not self.kernel.AssignProcessToJobObject(self.handle, info.process):
                self.kernel.TerminateProcess(info.process, 1)
                raise NativeError("cannot assign suspended worker to native Job Object")
            self.process = info.process
            if self.kernel.ResumeThread(info.thread) == 0xFFFFFFFF:
                raise NativeError("cannot resume contained native worker")
        finally:
            if info.thread:
                self.kernel.CloseHandle(info.thread)
            if info.process and not self.process:
                self.kernel.CloseHandle(info.process)
            self.kernel.CloseHandle(token)

    def wait(self, deadline: float, heartbeat) -> int:
        while True:
            outcome = self.kernel.WaitForSingleObject(self.process, 1000)
            if outcome == 0:
                break
            if outcome != 0x102:
                raise NativeError("native worker wait failed; termination is unproven")
            if time.monotonic() >= deadline:
                raise NativeError("offline worker exceeded its deadline")
            heartbeat()
        code = DWORD()
        if not self.kernel.GetExitCodeProcess(self.process, ctypes.byref(code)):
            raise NativeError("cannot read native worker exit code")
        return code.value

    def close(self) -> None:
        if self.handle:
            self.kernel.TerminateJobObject(self.handle, 1)
            self.kernel.CloseHandle(self.handle)
            self.handle = None
        if self.process:
            self.kernel.CloseHandle(self.process)
            self.process = None


def assert_worker(job: dict) -> None:
    """Reject direct _build calls outside this exact account and Job Object."""
    require_native()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.GetUserNameW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(DWORD)]
    username, length = ctypes.create_unicode_buffer(257), DWORD(257)
    if not advapi.GetUserNameW(username, ctypes.byref(length)) or username.value.casefold() != job["worker_account"].casefold():
        raise NativeError("native build must run as this job's ephemeral worker")
    kernel.GetCurrentProcess.restype = HANDLE
    kernel.OpenJobObjectW.argtypes = [DWORD, ctypes.c_int, ctypes.c_wchar_p]
    kernel.OpenJobObjectW.restype = HANDLE
    kernel.IsProcessInJob.argtypes = [HANDLE, HANDLE, ctypes.POINTER(ctypes.c_int)]
    kernel.CloseHandle.argtypes = [HANDLE]
    handle = kernel.OpenJobObjectW(4, False, job["job_object"])
    if not handle:
        raise NativeError("native worker cannot query the exact coordinator Job Object")
    try:
        member = ctypes.c_int()
        if not kernel.IsProcessInJob(kernel.GetCurrentProcess(), handle, ctypes.byref(member)) or not member.value:
            raise NativeError("native worker is outside its exact coordinator Job Object")
    finally:
        kernel.CloseHandle(handle)
