#!/usr/bin/env python3
"""Render the fail-closed Windows VirtIO driver signature gate for M15-03.

The gate is intentionally executed *inside* the prepared Windows guest.  A
host-side check of a catalog is useful transport evidence, but cannot replace
``signtool verify /kp /c`` on the actual Windows build host.  The resulting
PowerShell therefore checks the exact Server 2025 amd64 VirtIO bundles and
must succeed before the bootstrap invokes Sysprep.
"""

from __future__ import annotations


DRIVER_BUNDLES = (
    ("vioscsi", "vioscsi.cat", ("vioscsi.inf", "vioscsi.sys")),
    ("NetKVM", "netkvm.cat", ("netkvm.inf", "netkvm.sys", "netkvmp.exe")),
)


def render_gate() -> str:
    """Return a self-contained PowerShell gate with no host/credential input."""
    bundle_rows = "\n".join(
        "    [ordered]@{ Driver = '%s'; Catalog = '%s'; Files = @(%s) }"
        % (bundle[0], bundle[1], ", ".join("'%s'" % file_name for file_name in bundle[2]))
        for bundle in DRIVER_BUNDLES
    )
    return f'''# Fail closed: this script is a required pre-Sysprep gate for GB100-M15-03.
# A host-side catalog check is deliberately not accepted as this verification.
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z]:$')][string]$MediaDrive,
  [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
  [Parameter(Mandatory = $true)][string]$SignTool
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if (-not (Test-Path -LiteralPath $SignTool -PathType Leaf)) {{ throw 'explicit signtool.exe is required before Sysprep' }}
$signTool = (Resolve-Path -LiteralPath $SignTool -ErrorAction Stop).Path
$mediaRoot = $MediaDrive + '\\'
$bundles = @(
{bundle_rows}
)
$records = New-Object System.Collections.Generic.List[object]

function Add-Record([string]$Path, [string]$Sha256, [string]$Result) {{
  [void]$records.Add([ordered]@{{ path = $Path; sha256 = $Sha256; result = $Result }})
}}

function Write-EvidenceAtomically() {{
  if (-not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) {{
    New-Item -ItemType Directory -Path $EvidenceDirectory -Force -ErrorAction Stop | Out-Null
  }}
  $destination = Join-Path $EvidenceDirectory 'virtio-signature-gate.json'
  if (Test-Path -LiteralPath $destination) {{ throw 'refusing to overwrite existing signature-gate evidence' }}
  $temporary = Join-Path $EvidenceDirectory ('.virtio-signature-gate-' + [guid]::NewGuid().ToString('N') + '.tmp')
  try {{
    [System.IO.File]::WriteAllText($temporary, (@($records) | ConvertTo-Json -Compress), [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $destination -ErrorAction Stop
  }} finally {{
    if (Test-Path -LiteralPath $temporary) {{ Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }}
  }}
}}

function Require-File([string]$Path) {{
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {{ throw "required VirtIO file is missing: $Path" }}
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash.ToLowerInvariant()
}}

function Invoke-SignTool([string[]]$Arguments) {{
  # Microsoft catalog-membership semantics: signtool verify /kp /v /c <CAT> <INF-or-SYS>.
  & $signTool @Arguments *>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw 'signtool verification failed' }}
}}

function Verify-Catalog([string]$Catalog) {{
  $hash = ''
  try {{
    $hash = Require-File $Catalog
    Invoke-SignTool @('verify', '/kp', '/v', $Catalog)
    Add-Record $Catalog $hash 'passed_catalog_signature'
  }} catch {{
    Add-Record $Catalog $hash 'failed'
    throw
  }}
}}

function Verify-CatalogMember([string]$Catalog, [string]$File) {{
  $hash = ''
  try {{
    $hash = Require-File $File
    Invoke-SignTool @('verify', '/kp', '/v', '/c', $Catalog, $File)
    Add-Record $File $hash 'passed_catalog_membership'
  }} catch {{
    Add-Record $File $hash 'failed'
    throw
  }}
}}

try {{
  foreach ($bundle in $bundles) {{
    $bundleRoot = Join-Path $mediaRoot ($bundle.Driver + '\\2k25\\amd64')
    $catalog = Join-Path $bundleRoot $bundle.Catalog
    Verify-Catalog $catalog
    foreach ($fileName in $bundle.Files) {{
      $file = Join-Path $bundleRoot $fileName
      Verify-CatalogMember $catalog $file
    }}
  }}
  Write-EvidenceAtomically
}} catch {{
  try {{ Write-EvidenceAtomically }} catch {{ }}
  throw
}}
'''
