#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$SourceDirectory="$PSScriptRoot\publish")
$ErrorActionPreference='Stop'
$service=Get-Service NetSentinelAgent -ErrorAction Stop
$install=Join-Path $env:ProgramFiles 'NetSentinel\Agent'
$source=(Resolve-Path -LiteralPath $SourceDirectory).Path
$candidate=Join-Path $source 'NetSentinel.Agent.exe'
$installed=Join-Path $install 'NetSentinel.Agent.exe'
if(-not(Test-Path -LiteralPath $candidate)){throw 'Published NetSentinel.Agent.exe was not found'}
if(-not(Test-Path -LiteralPath $installed)){throw 'Installed NetSentinel Agent binary was not found'}
$backup=Join-Path $env:ProgramData ('NetSentinel\Agent\upgrade-backup-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $backup | Out-Null
try{
    Stop-Service NetSentinelAgent
    Copy-Item -LiteralPath $install -Destination $backup -Recurse
    Copy-Item -Path (Join-Path $source '*') -Destination $install -Recurse -Force
    Start-Service NetSentinelAgent
    $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    Write-Host 'NetSentinel Agent upgraded. Enrollment identity and DPAPI credentials were preserved.'
}catch{
    Stop-Service NetSentinelAgent -Force -ErrorAction SilentlyContinue
    Copy-Item -Path (Join-Path $backup 'Agent\*') -Destination $install -Recurse -Force
    Start-Service NetSentinelAgent
    throw
}finally{
    if(Test-Path -LiteralPath $backup){Remove-Item -LiteralPath $backup -Recurse -Force}
}
