function Get-ScriptVariables{
  [CmdLetBinding()]
  param(
    [Parameter(Mandatory = $true,ParameterSetName = 'JSON')][ValidateNotNullOrEmpty()][String]$JSON,
    [Parameter(Mandatory = $true,ParameterSetName = 'URI')][ValidateNotNullOrEmpty()][String]$URI,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$Environment,
    [Parameter()][ValidateNotNullOrEmpty()][String]$Script
  )
  # If path to JSON file is selected
  if($JSON){
    $vars = Get-Content -Path $JSON | ConvertFrom-JSON -Depth 10
  }
  # If a URI to a JSON is provided
  else{
    $vars = (Invoke-WebRequest -Uri $URI -Method "GET" -UseBasicParsing).Content | ConvertFrom-JSON -Depth 10
  }
  foreach ($var in $vars.PSObject.Properties) {
    if($var.Name -eq "Environment"){
      foreach($item in $var.Value.PSObject.Properties){
        if($item.Name -eq $Environment){
          foreach($obj in $item.Value.PSObject.Properties){
            Set-Variable -Name $obj.Name -Value $obj.Value -Scope Global
          }
          break
        }
      }
    }
    elseif($var.Name -eq "ScriptSpecific"){
      foreach($item in $var.Value.PSObject.Properties){
        if($item.Name -eq $Script){
          foreach($obj in $item.Value.PSObject.Properties){
            Set-Variable -Name $obj.Name -Value $obj.Value -Scope Global
          }
          break
        }
      }
    }
    else{
      Set-Variable -Name $var.Name -Value $var.Value -Scope Global
    }
  }
}