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
$installLog = Join-Path $data 'install.log'
$script:InstallStage = 'initialization'

function Write-InstallLog([string]$Message) {
    $line = '{0:o} [{1}] {2}' -f [DateTimeOffset]::Now,$script:InstallStage,$Message
    Add-Content -LiteralPath $installLog -Value $line -Encoding UTF8
}

function Invoke-ServiceController([string[]]$Arguments,[string]$FailureMessage) {
    $output = & sc.exe @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($output) { Write-InstallLog (($output | ForEach-Object { $_.ToString().Trim() }) -join ' ') }
    if ($exitCode -ne 0) { throw "$FailureMessage (sc.exe exit code $exitCode)" }
}

function Stop-AgentService([string]$Name) {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        Stop-Service -Name $Name -Force
        $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(20))
    }
}

function Install-AgentService([string]$Name,[string]$ExecutablePath,[string]$ExecutableArguments,[string]$Account,[string]$Description) {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    $quotedBinaryPath = '"{0}"' -f $ExecutablePath
    if ($ExecutableArguments) { $quotedBinaryPath += " $ExecutableArguments" }
    if ($service) {
        Invoke-ServiceController @('config',$Name,"binPath= $quotedBinaryPath",'start= auto',"obj= $Account") "$Name service update failed"
    } else {
        Invoke-ServiceController @('create',$Name,"binPath= $quotedBinaryPath",'start= auto',"obj= $Account") "$Name service registration failed"
    }
    Invoke-ServiceController @('description',$Name,$Description) "$Name service description failed"
}

function Start-AgentService([string]$Name) {
    Start-Service -Name $Name
    $service = Get-Service -Name $Name
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(20))
    $service.Refresh()
    if ($service.Status -ne 'Running') { throw "$Name did not remain in the Running state" }
}

if (-not (Test-Path -LiteralPath $exe)) { throw 'NetSentinel Agent binary is missing from the installation directory' }
if ($ServerUrl.StartsWith('http://',[StringComparison]::OrdinalIgnoreCase) -and -not $AllowHttp) {
    throw 'HTTP is disabled. Use an HTTPS server URL or explicitly enable controlled-lab HTTP.'
}

New-Item -ItemType Directory -Force -Path $data,$logs | Out-Null
try {
    Write-InstallLog 'Installation/configuration started.'
    $ServerUrl = $ServerUrl.Trim()
    $RequestedControlMode = $RequestedControlMode.Trim().ToUpperInvariant()
    $script:InstallStage = 'stop-existing-services'
    Stop-AgentService 'NetSentinelAgent'
    Stop-AgentService 'NetSentinelMaintenance'

$script:InstallStage = 'data-directory-acl'
$acl = Get-Acl $data
$acl.SetAccessRuleProtection($true,$false)
@('SYSTEM','BUILTIN\Administrators','NT AUTHORITY\LOCAL SERVICE') | ForEach-Object {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($_,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
Set-Acl -Path $data -AclObject $acl

$script:InstallStage = 'winhttp-acl'
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


$script:InstallStage = 'browser-policy-acl'
@('SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings','SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings','SOFTWARE\Policies\Microsoft\Edge','SOFTWARE\Policies\Google\Chrome','SOFTWARE\Policies\Mozilla\Firefox\Proxy') | ForEach-Object {
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

$script:InstallStage = 'agent-configuration'
$configure = @('configure','--server',$ServerUrl,'--portal-approval','--control-mode',$RequestedControlMode)
if ($AllowHttp) { $configure += '--allow-http' }
Write-InstallLog ("Configuring scheme={0}, host={1}, port={2}, allowHttp={3}, mode={4}" -f ([Uri]$ServerUrl).Scheme,([Uri]$ServerUrl).Host,([Uri]$ServerUrl).Port,[bool]$AllowHttp,$RequestedControlMode)
$configurationOutput = & $exe @configure 2>&1
$configurationExitCode = $LASTEXITCODE
if ($configurationOutput) { Write-InstallLog (($configurationOutput | ForEach-Object { $_.ToString().Trim() }) -join ' ') }
if ($configurationExitCode -ne 0) { throw "Agent configuration failed with exit code $configurationExitCode" }

$script:InstallStage = 'service-registration'
Install-AgentService 'NetSentinelAgent' $exe '' 'NT AUTHORITY\LocalService' 'NetSentinel endpoint management service'
Install-AgentService 'NetSentinelMaintenance' $exe 'maintenance-service' 'LocalSystem' 'NetSentinel signed-command maintenance broker'
Invoke-ServiceController @('failure','NetSentinelAgent','reset= 86400','actions= restart/5000/restart/15000/restart/60000') 'NetSentinelAgent recovery configuration failed'
Invoke-ServiceController @('failure','NetSentinelMaintenance','reset= 86400','actions= restart/5000/restart/15000/restart/60000') 'NetSentinelMaintenance recovery configuration failed'

$script:InstallStage = 'maintenance-service-start'
Start-AgentService 'NetSentinelMaintenance'
$script:InstallStage = 'agent-service-start'
Start-AgentService 'NetSentinelAgent'
$script:InstallStage = 'complete'
Write-InstallLog 'Both Windows services are installed and running.'
Write-Host 'NetSentinel Agent installed. Portal administrator approval is now required.'
} catch {
    Write-InstallLog ("FAILED: {0}`r`n{1}" -f $_.Exception.Message,$_.ScriptStackTrace)
    Write-Error ("NetSentinel installation failed during '{0}': {1}. See {2}" -f $script:InstallStage,$_.Exception.Message,$installLog)
    exit 1
}
