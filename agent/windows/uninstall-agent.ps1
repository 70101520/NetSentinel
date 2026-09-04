#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$RemoveIdentity)
$ErrorActionPreference = 'Stop'
$service = Get-Service NetSentinelAgent -ErrorAction SilentlyContinue
if ($service) { if ($service.Status -ne 'Stopped') { Stop-Service NetSentinelAgent -Force }; sc.exe delete NetSentinelAgent | Out-Null }
$install = Join-Path $env:ProgramFiles 'NetSentinel\Agent'
if (Test-Path $install) { Remove-Item -LiteralPath $install -Recurse -Force }
if ($RemoveIdentity) {
    $data = Join-Path $env:ProgramData 'NetSentinel\Agent'
    if (Test-Path $data) { Remove-Item -LiteralPath $data -Recurse -Force }
}
Write-Host 'Service and binaries removed. Identity is retained unless -RemoveIdentity was supplied; server history is unchanged.'
