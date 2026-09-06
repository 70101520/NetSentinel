#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^https?://')][string]$ServerUrl,
    [Parameter(Mandatory)][string]$EnrollmentToken,
    [string]$SourceDirectory = "$PSScriptRoot\publish",
    [switch]$AllowHttp
)
$ErrorActionPreference = 'Stop'
$install = Join-Path $env:ProgramFiles 'NetSentinel\Agent'
$data = Join-Path $env:ProgramData 'NetSentinel\Agent'
New-Item -ItemType Directory -Force -Path $install,$data,(Join-Path $data 'Logs') | Out-Null
Copy-Item -Path (Join-Path $SourceDirectory '*') -Destination $install -Recurse -Force
$acl = Get-Acl $data
$acl.SetAccessRuleProtection($true,$false)
@('SYSTEM','BUILTIN\Administrators','NT AUTHORITY\LOCAL SERVICE') | ForEach-Object {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($_,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
Set-Acl -Path $data -AclObject $acl
$winHttpPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
$winHttpKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($winHttpPath,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[Security.AccessControl.RegistryRights]::ChangePermissions)
if (-not $winHttpKey) { throw 'WinHTTP connection-settings registry key is unavailable' }
$winHttpAcl = $winHttpKey.GetAccessControl()
$winHttpRights = [Security.AccessControl.RegistryRights]::QueryValues -bor [Security.AccessControl.RegistryRights]::SetValue
$winHttpRule = [Security.AccessControl.RegistryAccessRule]::new('NT AUTHORITY\LOCAL SERVICE',$winHttpRights,'None','None','Allow')
$winHttpAcl.AddAccessRule($winHttpRule) | Out-Null
$winHttpKey.SetAccessControl($winHttpAcl)
$winHttpKey.Dispose()
$exe = Join-Path $install 'NetSentinel.Agent.exe'
$configure = @('configure','--server',$ServerUrl,'--enrollment-token-stdin')
if ($AllowHttp) { $configure += '--allow-http' }
$EnrollmentToken | & $exe @configure
if (Get-Service NetSentinelAgent -ErrorAction SilentlyContinue) { throw 'NetSentinelAgent is already installed' }
sc.exe create NetSentinelAgent binPath= "`"$exe`"" start= auto obj= "NT AUTHORITY\LocalService" | Out-Null
sc.exe description NetSentinelAgent "NetSentinel endpoint enrollment and heartbeat service" | Out-Null
sc.exe failure NetSentinelAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
Start-Service NetSentinelAgent
Write-Host 'NetSentinel Agent installed and started.'
