function Get-AllowedAccess{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string[]]$Roles,
    [Parameter(Mandatory = $true)][string[]]$AllowedRoles
  )
  foreach($role in $AllowedRoles){
    if($Roles -contains $role){
      return $true
    }
  }
  return $false
}