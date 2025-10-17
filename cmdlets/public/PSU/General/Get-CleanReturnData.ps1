<#
.SYNOPSIS
    Returns a cleaned list of objects, omitting specified properties.

.DESCRIPTION
    The Get-CleanReturnData function takes an array of objects (hashtable or PSCustomObject) and returns a new list of PSCustomObjects.
    It copies all properties except those specified in the PropertiesToSkip parameter, allowing you to filter out unwanted properties from the output.

.PARAMETER Data
    The array of objects (Hashtable or PSCustomObject) to process.

.PARAMETER PropertiesToSkip
    An optional array of property names to exclude from the returned objects.

.EXAMPLE
    Get-CleanReturnData -Data $results -PropertiesToSkip 'Password','Secret'

    Returns a cleaned list of objects from $results, omitting the 'Password' and 'Secret' properties.

.EXAMPLE
    Get-CleanReturnData -Data $users

    Returns a cleaned list of objects from $users, including all properties.

.NOTES
    Author: Jeremy Putman
    Last Updated: 2025-10-11
#>
function Get-CleanReturnData {
  [cmdletbinding()]
  param(
    [Parameter(Mandatory = $true)][Object[]]$Data,
    [Parameter()][string[]]$PropertiesToSkip
  )
  # Get a list of the property names
  $item_properties = switch -Regex ($Data.GetType().Name) {
    'Hashtable' { $Data.Keys }
    'PSCustomObject' { $Data.psobject.Properties.Name }
    default { $Data | Get-Member -MemberType Property | Select-Object -Expand Name }
  }  
  # Create a clean list to return
  $return_data = [System.Collections.Generic.List[PSCustomObject]]::new()
  foreach ($item in $Data) {
    $obj = [PSCustomObject]@{}
    foreach($property in $item_properties){
      if($property -notin $PropertiesToSkip){
        if($item.$property.gettype().basetype.Name -eq "Enum"){
          $obj | Add-Member -NotePropertyName $property -NotePropertyValue $item.$property.tostring() -force
        }
        else{
          $obj | Add-Member -NotePropertyName $property -NotePropertyValue $item.$property -force
        }
      }
    }
    $return_data.Add($obj) | Out-Null
  }
  return $return_data
}