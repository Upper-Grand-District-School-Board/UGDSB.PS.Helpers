<#
  .DESCRIPTION 
  This is designed to get the device certificate for Entra that is enrolled. Originally from https://github.com/AdamGrossTX/ManagedUserManagement/blob/main/ClientScripts/Set-AutoLogon.ps1 by Adam Gross
#>
function Get-EntraDeviceCertificate {
  [CmdletBinding()]
  [OutputType([X509Certificate])]
  param (
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][Object]$dsregcmdStatus
  )
  try {
    Write-Host "Getting Azure AD Device Certificate"
    #Get best cert from DSRegCmd
    $Thumbprint = $dsregcmdstatus.DeviceDetails.Thumbprint
    #Get the local cert that matches the DSRegCMD Cert
    $Certs = Get-ChildItem -Path Cert:\LocalMachine\My 
    $Cert = $Certs | Where-Object { $_.Thumbprint -eq $dsregcmdstatus.DeviceDetails.Thumbprint }
    if ($Cert.Thumbprint -eq $Thumbprint) {
      return $Cert
    }
    else {
      Write-Output "No valid Entra Device Cert Found."
    }
  }
  catch {
    throw $_
  }
}
