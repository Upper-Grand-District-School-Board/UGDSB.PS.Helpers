<#
  .SYNOPSIS
      Determine if the device conforms to the requirement of being either Azure AD joined or Hybrid Azure AD joined.
  
  .DESCRIPTION
      Determine if the device conforms to the requirement of being either Azure AD joined or Hybrid Azure AD joined.
  
  .NOTES
      Author:      Nickolaj Andersen
      Contact:     @NickolajA
      Created:     2022-01-27
      Updated:     2022-01-27
  
      Version history:
      1.0.0 - (2022-01-27) Function created
  #>
function Test-EntraIDDeviceRegistration {
  [CmdletBinding()]
  param()  
  $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
  if (Test-Path -Path $EntraIDJoinInfoRegistryKeyPath) {
    return $true
  }
  else {
    return $false
  }
}