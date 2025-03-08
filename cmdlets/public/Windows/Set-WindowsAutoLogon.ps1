<#
  .DESCRIPTION 
  This is designed to enable windows autologon functionality. Originally from https://github.com/AdamGrossTX/ManagedUserManagement/blob/main/ClientScripts/Set-AutoLogon.ps1 by Adam Gross and https://github.com/mkht/DSCR_AutoLogon
#>
function Set-WindowsAutoLogon {
  [cmdletBinding()]
  param(
    [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][PSCredential]$Credential
  )
  try {
    if (-not (Test-LocalAdmin)) {
      Write-Error ('Administrator privilege is required to execute this command')
      return
    }
    Add-PInvokeType
    Write-Output "Enabling Autologon"
    $WinLogonKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path registry::$WinLogonKey -Name "AutoAdminLogon" -Value 1 -Force
    Set-ItemProperty -Path registry::$WinLogonKey -Name "DefaultUserName" -Value $Credential.UserName -Force
    Remove-ItemProperty -Path registry::$WinLogonKey -Name "AutoLogonCount" -ErrorAction SilentlyContinue
    Write-Verbose ('Password will be encrypted')
    Remove-ItemProperty -Path registry::$WinLogonKey -Name "DefaultPassword" -ErrorAction SilentlyContinue
    $private:LsaUtil = New-Object PInvoke.LSAUtil.LSAutil -ArgumentList "DefaultPassword"
    $LsaUtil.SetSecret($Credential.GetNetworkCredential().Password)
    Write-Verbose ('Auto logon has been enabled')
  }
  catch {
    throw $_
  }
}