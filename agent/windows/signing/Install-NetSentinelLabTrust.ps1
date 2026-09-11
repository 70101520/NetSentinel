#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][string]$CertificatePath
)

$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $CertificatePath).Path
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($resolved)
$codeSigningOid = '1.3.6.1.5.5.7.3.3'
$hasCodeSigningEku = $certificate.Extensions | Where-Object {
    $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] -and
    ($_.EnhancedKeyUsages | Where-Object Value -eq $codeSigningOid)
}

if ($certificate.Subject -ne 'CN=NetSentinel Internal Lab' -or -not $hasCodeSigningEku) {
    throw 'Refusing to trust a certificate that is not the NetSentinel internal lab code-signing certificate.'
}
if ($certificate.NotAfter -le (Get-Date)) { throw 'The lab signing certificate is expired.' }

$target = "$($certificate.Subject) [$($certificate.Thumbprint)]"
if ($PSCmdlet.ShouldProcess($target,'Trust for all users as Root and Trusted Publisher')) {
    Import-Certificate -FilePath $resolved -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath $resolved -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    Write-Host "Trusted NetSentinel lab publisher installed: $($certificate.Thumbprint)"
}

