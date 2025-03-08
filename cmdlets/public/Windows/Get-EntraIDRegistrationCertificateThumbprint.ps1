<#
  .SYNOPSIS
      Get the thumbprint of the certificate used for Azure AD device registration.
  
  .DESCRIPTION
      Get the thumbprint of the certificate used for Azure AD device registration.
  
  .NOTES
      Author:      Nickolaj Andersen
      Contact:     @NickolajA
      Created:     2021-06-03
      Updated:     2021-06-03
  
      Version history:
      1.0.0 - (2021-06-03) Function created
      1.0.1 - (2023-05-10) Max Updated for Cloud PCs which don't have their thumbprint as their JoinInfo key name.
  #>
function Get-EntraIDRegistrationCertificateThumbprint {
  [CmdletBinding()]
  param()  
  # Define Cloud Domain Join information registry path
  $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
  # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
  $EntraIDJoinInfoThumbprint = Get-ChildItem -Path $EntraIDJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
  # Check for a cert matching that thumbprint
  $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $EntraIDJoinInfoThumbprint }
  if ($EntraIDJoinCertificate -ne $null) {
    # if a matching cert was found tied to that reg key (thumbprint) value, then that is the thumbprint and it can be returned.
    $EntraIDThumbprint = $EntraIDJoinInfoThumbprint
    # Handle return value
    return $EntraIDThumbprint
  }
  else {
    # If a cert was not found, that reg key was not the thumbprint but can be used to locate the cert as it is likely the Azure ID which is in the certs common name.
    $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($EntraIDJoinInfoThumbprint)" }
    #Pull thumbprint from cert
    $EntraIDThumbprint = $EntraIDJoinCertificate.Thumbprint
    # Handle return value
    return $EntraIDThumbprint
  }
}