<#
  .DESCRIPTION 
  This is designed to get the entra id device id. Originally from https://azuretothemax.net/log-analytics-index/
#>
function Get-EntraIDDeviceID {
  [CmdletBinding()]
  param()  
  # Define Cloud Domain Join information registry path
  $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"

  # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
  $EntraIDJoinInfoThumbprint = Get-ChildItem -Path $EntraIDJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
  if ($EntraIDJoinInfoThumbprint -ne $null) {
    # Retrieve the machine certificate based on thumbprint from registry key
    $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $EntraIDJoinInfoThumbprint }
    if ($EntraIDJoinCertificate -ne $null) {
      # Determine the device identifier from the subject name
      $EntraIDDeviceID = ($EntraIDJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
      # Convert upper to lowercase.
      $EntraIDDeviceID = "$($EntraIDDeviceID)".ToLower()
      # Handle return value
      return $EntraIDDeviceID
    }
    else {
      #If no certificate was found, locate it by Common Name instead of Thumbprint. This is likely a CPC or similar.
      $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=($EntraIDJoinInfoThumbprint)" }
      if ($EntraIDJoinCertificate -ne $null) {
        # Cert is now found, extract Device ID from Common Name
        $EntraIDDeviceID = ($EntraIDJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
        # Convert upper to lowercase.
        $EntraIDDeviceID = "$($EntraIDDeviceID)".ToLower()
        # Handle return value
        return $EntraIDDeviceID
      }
      else {
        # Last ditch effort, try and use the ThumbPrint (reg key) itself.
        $EntraIDDeviceID = $EntraIDJoinInfoThumbprint
        # Convert upper to lowercase.
        $EntraIDDeviceID = "$($EntraIDDeviceID)".ToLower()
        return $EntraIDDeviceID
      }
    }
  }
}