<#
.SYNOPSIS
  Loads variables from a JSON or YAML file and sets them in the global scope.

.DESCRIPTION
  The Get-ScriptVariables function reads variables from a specified JSON or YAML file.
  It supports loading environment-specific or script-specific variables and sets them as global variables.
  Optionally, it can download the file from a URI before processing.

.PARAMETER JSON
  The path to the JSON file containing the variables.

.PARAMETER YAML
  The path to the YAML file containing the variables.

.PARAMETER URI
  (Optional) A URI to download the JSON or YAML file from before processing.

.PARAMETER Environment
  The environment section to load variables from (e.g., 'Production', 'Development').

.PARAMETER Script
  (Optional) The script section to load variables from.

.EXAMPLE
  Get-ScriptVariables -JSON '.\vars.json' -Environment 'Production'
  Loads variables from the 'Production' section of vars.json and sets them as global variables.

.EXAMPLE
  Get-ScriptVariables -YAML '.\vars.yaml' -Environment 'Development' -Script 'MyScript'
  Loads variables from the 'Development' > 'MyScript' section of vars.yaml and sets them as global variables.

.NOTES
  Author: Jeremy Putman
  Last Updated: 2025-10-11
#>
function Get-ScriptVariables {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true, ParameterSetName = 'JSON')][ValidateNotNullOrEmpty()][String]$JSON,
    [Parameter(Mandatory = $true, ParameterSetName = 'YAML')][ValidateNotNullOrEmpty()][String]$YAML,
    [Parameter()][ValidateNotNullOrEmpty()][String]$URI,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$Environment,
    [Parameter()][ValidateNotNullOrEmpty()][String]$Script
  )
  # If URI is set download the file to the temp folder
  if ($PSBoundParameters.ContainsKey("URI")) {
    $path = Join-Path -Path $env:TEMP -childpath ($PSBoundParameters.ContainsKey("JSON") ? $JSON : $YAML)
    Invoke-WebRequest -Uri $URI -OutFile $path -UseBasicParsing -ErrorAction Stop
    if ($PSBoundParameters.ContainsKey("JSON")) {
      $JSON = $path
    }
    else {
      $YAML = $path
    }
  }
  # If it is a JSON, read the file and get the keys
  if ($PSBoundParameters.ContainsKey("JSON")) {
    $vars = Get-Content -Path $JSON | ConvertFrom-JSON -Depth 10
    $keys = $vars.PSObject.Properties.Name
  }
  # Otherwise it would be a YAML file, so get the keys
  else {
    $vars = Get-Content -Path $YAML | ConvertFrom-Yaml
    $keys = $vars.keys
  }
  # Loop through the keys and set the variables in the global scope
  foreach ($key in $keys) {
    if ($key -eq "Environment" -or $key -eq "Scripts") {
      $section = ($key -eq "Environment") ? $Environment : $Script
      $variables = ($PSBoundParameters.ContainsKey("JSON"))  ? ($vars.$key.$section.PSObject.Properties.Name) : ($vars.$key.$section.keys)
      foreach ($variable in $variables) {
        Set-Variable -Name $variable -Value $vars.$key.$section.$variable -Scope Global
      }
    }
    else {
      Set-Variable -Name $key -Value $vars.$key -Scope Global 
    }
    
  }
}