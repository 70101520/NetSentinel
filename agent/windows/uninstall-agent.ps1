#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$RemoveIdentity)
$ErrorActionPreference = 'Stop'
$service = Get-Service NetSentinelAgent -ErrorAction SilentlyContinue
$install = Join-Path $env:ProgramFiles 'NetSentinel\Agent'
if ($service -and $service.Status -ne 'Stopped') { Stop-Service NetSentinelAgent -Force }
$executable = Join-Path $install 'NetSentinel.Agent.exe'
$baseline = Join-Path $env:ProgramData 'NetSentinel\Agent\proxy-baseline.json'
if ((Test-Path -LiteralPath $executable) -and (Test-Path -LiteralPath $baseline)) { & $executable restore-proxy; if ($LASTEXITCODE -ne 0) { throw 'Proxy baseline restoration failed; uninstall stopped safely' } }
if ($service) { sc.exe delete NetSentinelAgent | Out-Null }
if (Test-Path $install) { Remove-Item -LiteralPath $install -Recurse -Force }
if ($RemoveIdentity) {
    $data = Join-Path $env:ProgramData 'NetSentinel\Agent'
    if (Test-Path $data) { Remove-Item -LiteralPath $data -Recurse -Force }
}
Write-Host 'Service and binaries removed. Identity is retained unless -RemoveIdentity was supplied; server history is unchanged.'
