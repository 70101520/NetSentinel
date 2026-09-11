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
$desktopShortcut=Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'NetSentinel Agent Settings.lnk'
if(Test-Path -LiteralPath $desktopShortcut){Remove-Item -LiteralPath $desktopShortcut -Force}
$uninstallKeys=@(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{35ED1F1C-94CE-40D8-A7C0-95C714847F33}_is1',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{35ED1F1C-94CE-40D8-A7C0-95C714847F33}_is1'
)
$uninstallKeys|Where-Object{Test-Path -LiteralPath $_}|ForEach-Object{Remove-Item -LiteralPath $_ -Recurse -Force}
if($RemoveIdentity){
    $data=Join-Path $env:ProgramData 'NetSentinel\Agent'
    if(Test-Path -LiteralPath $data){Remove-Item -LiteralPath $data -Recurse -Force}
}
Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
