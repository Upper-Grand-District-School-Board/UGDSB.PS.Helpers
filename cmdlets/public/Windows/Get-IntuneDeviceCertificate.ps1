<#
  .DESCRIPTION 
  This is designed to get the device certificate for Intune that is enrolled. Originally from https://github.com/AdamGrossTX/ManagedUserManagement/blob/main/ClientScripts/Set-AutoLogon.ps1 by Adam Gross
#>
function Get-IntuneDeviceCertificate {
  [CmdletBinding()]
  [OutputType([X509Certificate])]
  param (
  )
  try {
    $CertIssuer = "CN=Microsoft Intune MDM Device CA"
    $ProviderRegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments"
    $ProviderPropertyName = "ProviderID"
    $ProviderPropertyValue = "MS DM Server"
    $ProviderGUID = (Get-ChildItem -Path Registry::$ProviderRegistryPath -Recurse | ForEach-Object { if ((Get-ItemProperty -Name $ProviderPropertyName -Path $_.PSPath -ErrorAction SilentlyContinue | Get-ItemPropertyValue -Name $ProviderPropertyName -ErrorAction SilentlyContinue) -match $ProviderPropertyValue) { $_ } }).PSChildName
    $DMClientPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\$($ProviderGUID)\DMClient\MS DM Server"
    $IntuneDeviceId = (Get-ItemPropertyValue -Path Registry::$DMClientPath -Name "EntDMID")

    $Cert = (Get-ChildItem cert:\LocalMachine\my | where-object { $_.Issuer -in $CertIssuer -and $_.Subject -like "*$IntuneDeviceId*" })
    if ($cert) {
      return $Cert
    }
  }
  catch {
    throw $_
  }  
}