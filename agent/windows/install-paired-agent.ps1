#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^https?://')][string]$ServerUrl,
    [switch]$AllowHttp,
    [ValidateSet('MONITOR_ONLY','WEB_CONTROLLED')][string]$RequestedControlMode='MONITOR_ONLY'
)

$ErrorActionPreference = 'Stop'
$install = Join-Path $env:ProgramFiles 'NetSentinel\Agent'
$data = Join-Path $env:ProgramData 'NetSentinel\Agent'
$logs = Join-Path $data 'Logs'
$exe = Join-Path $install 'NetSentinel.Agent.exe'

if (-not (Test-Path -LiteralPath $exe)) { throw 'NetSentinel Agent binary is missing from the installation directory' }
if ($ServerUrl.StartsWith('http://',[StringComparison]::OrdinalIgnoreCase) -and -not $AllowHttp) {
    throw 'HTTP is disabled. Use an HTTPS server URL or explicitly enable controlled-lab HTTP.'
}

New-Item -ItemType Directory -Force -Path $data,$logs | Out-Null
$acl = Get-Acl $data
$acl.SetAccessRuleProtection($true,$false)
@('SYSTEM','BUILTIN\Administrators','NT AUTHORITY\LOCAL SERVICE') | ForEach-Object {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($_,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
Set-Acl -Path $data -AclObject $acl

$winHttpPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
$winHttpKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($winHttpPath,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[Security.AccessControl.RegistryRights]::ChangePermissions)
if (-not $winHttpKey) { throw 'WinHTTP connection-settings registry key is unavailable' }
try {
    $winHttpAcl = $winHttpKey.GetAccessControl()
    $winHttpRights = [Security.AccessControl.RegistryRights]::QueryValues -bor [Security.AccessControl.RegistryRights]::SetValue
    $winHttpRule = [Security.AccessControl.RegistryAccessRule]::new('NT AUTHORITY\LOCAL SERVICE',$winHttpRights,'None','None','Allow')
    $winHttpAcl.AddAccessRule($winHttpRule) | Out-Null
    $winHttpKey.SetAccessControl($winHttpAcl)
} finally { $winHttpKey.Dispose() }


@('SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings','SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings','SOFTWARE\Policies\Microsoft\Edge','SOFTWARE\Policies\Google\Chrome') | ForEach-Object {
    $proxyKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($_,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
    if (-not $proxyKey) { throw "Machine proxy registry key is unavailable: $_" }
    try {
        $proxyAcl = $proxyKey.GetAccessControl()
        $proxyRights = [Security.AccessControl.RegistryRights]::QueryValues -bor [Security.AccessControl.RegistryRights]::SetValue -bor [Security.AccessControl.RegistryRights]::CreateSubKey
        $proxyRule = [Security.AccessControl.RegistryAccessRule]::new('NT AUTHORITY\LOCAL SERVICE',$proxyRights,'None','None','Allow')
        $proxyAcl.AddAccessRule($proxyRule) | Out-Null
        $proxyKey.SetAccessControl($proxyAcl)
    } finally { $proxyKey.Dispose() }
}

$configure = @('configure','--server',$ServerUrl,'--portal-approval','--control-mode',$RequestedControlMode)
if ($AllowHttp) { $configure += '--allow-http' }
& $exe @configure
if ($LASTEXITCODE -ne 0) { throw "Agent configuration failed with exit code $LASTEXITCODE" }

$service = Get-Service NetSentinelAgent -ErrorAction SilentlyContinue
if (-not $service) {
    sc.exe create NetSentinelAgent binPath= "`"$exe`"" start= auto obj= "NT AUTHORITY\LocalService" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Windows service registration failed' }
    sc.exe description NetSentinelAgent "NetSentinel endpoint management service" | Out-Null
    sc.exe failure NetSentinelAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
} else {
    sc.exe config NetSentinelAgent binPath= "`"$exe`"" start= auto obj= "NT AUTHORITY\LocalService" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Windows service update failed' }
}

Start-Service NetSentinelAgent
Write-Host 'NetSentinel Agent installed. Portal administrator approval is now required.'
