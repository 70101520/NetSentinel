#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][guid]$CommandId,[switch]$RemoveIdentity)
$ErrorActionPreference='Stop'
Start-Sleep -Seconds 3
@('NetSentinelAgent','NetSentinelMaintenance') | ForEach-Object {
    $service=Get-Service $_ -ErrorAction SilentlyContinue
    if($service -and $service.Status -ne 'Stopped'){Stop-Service $_ -Force -ErrorAction SilentlyContinue}
}
Start-Sleep -Seconds 2
sc.exe delete NetSentinelAgent | Out-Null
sc.exe delete NetSentinelMaintenance | Out-Null
$install=Join-Path $env:ProgramFiles 'NetSentinel\Agent'
if(Test-Path -LiteralPath $install){Remove-Item -LiteralPath $install -Recurse -Force}
if($RemoveIdentity){
    $data=Join-Path $env:ProgramData 'NetSentinel\Agent'
    if(Test-Path -LiteralPath $data){Remove-Item -LiteralPath $data -Recurse -Force}
}
Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
