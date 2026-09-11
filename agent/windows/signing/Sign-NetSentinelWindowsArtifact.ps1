#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory)][string[]]$Path,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$certificate = Get-Item "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction Stop
if (-not $certificate.HasPrivateKey) { throw 'The signing certificate private key is unavailable.' }

$signTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $signTool) { throw 'signtool.exe was not found. Install the Windows SDK.' }

foreach ($item in $Path) {
    $resolved = (Resolve-Path -LiteralPath $item).Path
    & $signTool sign /sha1 $certificate.Thumbprint /s My /fd SHA256 /tr $TimestampUrl /td SHA256 $resolved
    if ($LASTEXITCODE -ne 0) { throw "Signing failed for $resolved" }
    & $signTool verify /pa /v $resolved
    if ($LASTEXITCODE -ne 0) { throw "Signature verification failed for $resolved" }
}

