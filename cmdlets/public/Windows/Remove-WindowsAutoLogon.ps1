<#
  .DESCRIPTION 
  This is designed to disable windows autologon functionality. Originally from https://github.com/AdamGrossTX/ManagedUserManagement/blob/main/ClientScripts/Set-AutoLogon.ps1 by Adam Gross and https://github.com/mkht/DSCR_AutoLogon
#>
function Remove-WindowsAutoLogon {
  [cmdletbinding()]
  param ()
  try {
    if (-not (Test-LocalAdmin)) {
      Write-Error ('Administrator privilege is required to execute this command')
      return
    }
    Add-PInvokeType
    Write-Output "Disabling AutoLogon"
    $WinLogonKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path registry::$WinLogonKey -Name "AutoAdminLogon" -Value 0 -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path registry::$WinLogonKey -Name "DefaultPassword" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path registry::$WinLogonKey -Name "DefaultUserName" -ErrorAction SilentlyContinue
    $private:LsaUtil = New-Object PInvoke.LSAUtil.LSAutil -ArgumentList "DefaultPassword"
    if ($LsaUtil.GetSecret()) {
      $LsaUtil.SetSecret($null) #Clear existing password
    }
    Write-Verbose ('Auto logon has been disabled')
  }
  catch {
    throw $_
  }
}