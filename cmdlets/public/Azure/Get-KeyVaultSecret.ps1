<#
  .DESCRIPTION
  This cmdlet is used to connect to a keyvault as the machine identity of the Azure Machine it is running under.
  .PARAMETER vaultName
  The name of the vault that we want to check
  .PARAMETER secretName
  The name of the secret we want to recover
  .EXAMPLE
  Check a secret out of a specific vault
    Get-KeyVaultSecret -vaultName <VAULT> -secretName <SECRET>
#>
function Get-KeyVaultSecret{
  [CmdletBinding()]
  [OutputType([System.String])]
  param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$vaultName,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$secretName
  )
  # The URI for the vault that we want to access
  $keyVaultURI = "https://$($vaultName).vault.azure.net/secrets/$($secretName)?api-version=2016-10-01"
  # Using the identity of the virtual machine account running the script
  $response = Invoke-RestMethod -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net' -Method GET -Headers @{Metadata="true"}
  # What the vault token is
  $keyVaultToken = $response.access_token
  try{
    # Get the relevant secret and return it
    $secret = Invoke-RestMethod -Uri $keyVaultURI -Method GET -Headers @{Authorization="Bearer $KeyVaultToken"}
    return $secret.Value | ConvertFrom-Json
  }
  # Error handling possible expected errors
  catch{
    if(($Error[0] -match "The remote name could not be resolved")){
      $message = "Error: Attempting to connect to Azure Key vault URI $($keyVaultURI)`n$($_)"
    }
    elseif(($Error[0] -match "Unauthorized")){
      $message = "Error: No authorization to Azure Key Vault  URI $($keyVaultURI)`n$($_)"
    }
    elseif(($Error[0] -match "SecretNotFound")){
      $message = "Error: The secret $($secretName) is not found in Azure Key Vault  URI $($keyVaultURI)`n$($_)"
    }
    else{
      $message = "Error: Unknown error connection to Azure Key vault URI $($keyVaultURI)`n$($_)"
    }
    Write-EventLog -LogName "Application" -Source "PowerShell Universal Scripts" -EntryType "Warning" -EventId 1001 -Message $message
    return $message
  }
}