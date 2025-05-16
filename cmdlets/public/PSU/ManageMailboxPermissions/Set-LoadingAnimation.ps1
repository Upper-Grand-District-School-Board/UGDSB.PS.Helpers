function Set-LoadingAnimation {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string[]]$permissionType
  )
  foreach ($obj in $permissionType) {
    Set-UDElement -Id $obj -Content {
      New-UDImage -Url "/assets/LoadingCircle.gif" -Width 250 -Height 250
    }
  }
}