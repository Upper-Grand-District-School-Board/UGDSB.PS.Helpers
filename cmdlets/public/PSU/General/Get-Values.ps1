<#
  .DESCRIPTION
  This cmdlet is designed to help PSU scripts for display of values
  .PARAMETER fields
  What fields to display
#>
function Get-Values(){
  param(
    [Parameter(Mandatory)][string[]]$fields,
    [Parameter(Mandatory)][PSCustomObject]$item
  )  
  $value = ""
  # Loop through the array to take not of what values were selected, and then return that value.
  foreach($i in $fields){
    if($item.$i){
      if($i.Contains('-1')){$value += $i.Substring(0,$i.Length-2) + ","}
      else{$value += $i + ","}
    }
  }
  return $value.Replace("-"," ")
}