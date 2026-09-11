#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$Subject = 'CN=NetSentinel Internal Lab',
    [int]$ValidityYears = 3,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
if ($ValidityYears -lt 1 -or $ValidityYears -gt 5) { throw 'ValidityYears must be between 1 and 5.' }
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $PSScriptRoot '..\..\..\certificates\netsentinel-lab'
}

$output = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().User
$privateAcl = [Security.AccessControl.DirectorySecurity]::new()
$privateAcl.SetOwner($currentUser)
$privateAcl.SetAccessRuleProtection($true,$false)
$inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
$propagation = [Security.AccessControl.PropagationFlags]::None
@(
    $currentUser,
    [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid,$null),
    [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,$null)
) | ForEach-Object {
    $privateAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($_,[Security.AccessControl.FileSystemRights]::FullControl,$inheritance,$propagation,[Security.AccessControl.AccessControlType]::Allow))
}
Set-Acl -LiteralPath $output -AclObject $privateAcl

$pfxPath = Join-Path $output 'NetSentinel-Lab-Code-Signing.pfx'
$cerPath = Join-Path $output 'NetSentinel-Lab-Code-Signing.cer'
$base64Path = Join-Path $output 'github-secret-pfx-base64.txt'
$passwordPath = Join-Path $output 'github-secret-pfx-password.txt'
if (-not $Force -and (@($pfxPath,$base64Path,$passwordPath) | Where-Object { Test-Path -LiteralPath $_ })) {
    throw "Private signing material already exists in $output. Reuse it; specify -Force only for an intentional certificate-secret rotation."
}

$existing = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
    $_.Subject -eq $Subject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddMonths(3)
} | Sort-Object NotAfter -Descending | Select-Object -First 1

if ($existing) {
    $certificate = $existing
} else {
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -FriendlyName 'NetSentinel internal lab code signing' `
        -CertStoreLocation Cert:\CurrentUser\My `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddYears($ValidityYears)
}

$random = [byte[]]::new(32)
$generator = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $generator.GetBytes($random) } finally { $generator.Dispose() }
$plainPassword = [Convert]::ToBase64String($random).TrimEnd('=').Replace('+','-').Replace('/','_')
$securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
Export-PfxCertificate -Cert $certificate -FilePath $pfxPath -Password $securePassword -ChainOption EndEntityCertOnly -CryptoAlgorithmOption AES256_SHA256 | Out-Null
Export-Certificate -Cert $certificate -FilePath $cerPath -Type CERT | Out-Null
[IO.File]::WriteAllText($base64Path,[Convert]::ToBase64String([IO.File]::ReadAllBytes($pfxPath)))
[IO.File]::WriteAllText($passwordPath,$plainPassword)

Write-Host "Lab signing certificate ready: $($certificate.Thumbprint)"
Write-Host "Public certificate (safe to distribute): $cerPath"
Write-Host "PRIVATE files (never commit/share): $pfxPath, $base64Path, $passwordPath"
Write-Host 'Create GitHub Actions secrets NETSENTINEL_LAB_SIGNING_PFX_BASE64 and NETSENTINEL_LAB_SIGNING_PASSWORD from the two github-secret files.'
