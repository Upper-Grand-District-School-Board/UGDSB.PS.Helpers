<#
  .DESCRIPTION
  This cmdlet is designed to help PSU scripts for display of yes/no
  .PARAMETER fields
  What fields to display
#>
function Get-YesNo(){
  [CmdletBinding()]
  [OutputType([string])]
  param(
    [Parameter(Mandatory = $true)][string[]]$fields,
    [Parameter(Mandatory)][PSCustomObject]$item
  )
  # Loop through values that are passed, and if exist, return yes, otherwise return No
  foreach($i in $fields){
    if($item.$i){return "Yes"}
  }
  return "No"
}  