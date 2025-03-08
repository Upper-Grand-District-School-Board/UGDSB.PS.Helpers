<#
  .DESCRIPTION 
  This is designed to get the entra id join date. Originally from https://azuretothemax.net/log-analytics-index/
#>
function Get-EntraIDJoinDate {
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
      $EntraIDJoinDate = ($EntraIDJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
      # Handle return value
      return $EntraIDJoinDate
    }
    if ($EntraIDJoinCertificate -eq $null) {
      $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -eq "CN=$($EntraIDJoinInfoThumbprint)" }
      $EntraIDJoinDate = ($EntraIDJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
      return $EntraIDJoinDate
    }
  }
}