<#
  .DESCRIPTION 
  This is designed to get the entra tenant id that device belogs too. Originally from https://azuretothemax.net/log-analytics-index/
#>
function Get-EntraIDTenantID{
  [CmdletBinding()]
  param()  
  # Cloud Join information registry path
  $EntraIDTenantInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
  # Retrieve the child key name that is the tenant id for EntraID
  $EntraIDTenantID = Get-ChildItem -Path $EntraIDTenantInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
  return $EntraIDTenantID  
}